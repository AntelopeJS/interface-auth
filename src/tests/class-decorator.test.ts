import { expect } from "chai";
import { Authentication } from "..";

class Guarded {}

const WITHOUT_PROTOTYPE = Guarded.bind(null);

describe("class decorator target", () => {
  it("refuses a class that has no prototype object", () => {
    expect(() => {
      Authentication()(WITHOUT_PROTOTYPE);
    }).to.throw(TypeError, "A class decorator applies to a class.");
  });

  it("accepts a class with a prototype object", () => {
    expect(() => {
      Authentication()(Guarded);
    }).not.to.throw();
  });
});
