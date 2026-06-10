"use strict";

const { EventEmitter } = require("events");
const Module = require("module");
const { expect } = require("chai");
const sinon = require("sinon");

describe("adapter startup data source selection", () => {
  let createAdapter;
  let adapterCorePath;
  let originalAdapterCore;

  before(() => {
    adapterCorePath = require.resolve("@iobroker/adapter-core");
    originalAdapterCore = require.cache[adapterCorePath];

    class TestAdapter extends EventEmitter {
      constructor(options) {
        super();
        this.config = options.config || {};
        this.log = {
          debug: sinon.spy(),
          error: sinon.spy(),
          info: sinon.spy(),
          warn: sinon.spy(),
        };
      }
    }

    const adapterCoreMock = new Module(adapterCorePath);
    adapterCoreMock.filename = adapterCorePath;
    adapterCoreMock.loaded = true;
    adapterCoreMock.exports = { Adapter: TestAdapter };
    require.cache[adapterCorePath] = adapterCoreMock;
    delete require.cache[require.resolve("./main")];
    createAdapter = require("./main");
  });

  after(() => {
    delete require.cache[require.resolve("./main")];
    if (originalAdapterCore) {
      require.cache[adapterCorePath] = originalAdapterCore;
    } else {
      delete require.cache[adapterCorePath];
    }
  });

  function createStartupAdapter(type) {
    const adapter = createAdapter({
      config: {
        password: "test-password",
        type,
      },
    });

    adapter.setState = sinon.spy();
    adapter.subscribeStates = sinon.spy();
    adapter.runEuDataAct = sinon.stub().resolves();
    adapter.login = sinon.stub().returns(new Promise(() => {}));
    adapter.getPersonalData = sinon.spy();
    adapter.getVehicles = sinon.spy();
    adapter.getSeatCupraStatus = sinon.spy();

    return adapter;
  }

  it("uses EU Data Act only for My CUPRA", async () => {
    const adapter = createStartupAdapter("seatcupra");

    await adapter.onReady();

    expect(adapter.runEuDataAct).to.have.been.calledOnceWithExactly("CUPRA");
    expect(adapter.login).not.to.have.been.called;
    expect(adapter.getPersonalData).not.to.have.been.called;
    expect(adapter.getVehicles).not.to.have.been.called;
    expect(adapter.getSeatCupraStatus).not.to.have.been.called;
    expect(adapter.subscribeStates).to.have.been.calledOnceWithExactly("*");
    expect(adapter.log.info).to.have.been.calledWithExactly(
      "My CUPRA: legacy OLA detail API is blocked by missing-device-token. " +
        "Using EU Data Act as the only data source.",
    );
  });

  it("keeps the VW ID EU Data Act-only startup behavior", async () => {
    const adapter = createStartupAdapter("id");

    await adapter.onReady();

    expect(adapter.runEuDataAct).to.have.been.calledOnceWithExactly("VOLKSWAGEN_PASSENGER_CARS");
    expect(adapter.login).not.to.have.been.called;
    expect(adapter.subscribeStates).to.have.been.calledOnceWithExactly("*");
  });

  for (const [type, brand] of [
    ["seat", "SEAT"],
    ["audietron", "AUDI"],
  ]) {
    it(`keeps the legacy login startup behavior for ${type}`, async () => {
      const adapter = createStartupAdapter(type);

      await adapter.onReady();

      expect(adapter.runEuDataAct).to.have.been.calledOnceWithExactly(brand);
      expect(adapter.login).to.have.been.calledOnce;
      expect(adapter.subscribeStates).to.have.been.calledOnceWithExactly("*");
    });
  }
});
