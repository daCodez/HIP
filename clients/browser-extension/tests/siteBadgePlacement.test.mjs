import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/siteBadgePlacement.js", import.meta.url), "utf8");
const context = vm.createContext({});
vm.runInContext(source, context);
const placement = context.HipSiteBadgePlacement;

function badge(position = null) {
  const attributes = new Map();
  const styles = new Map();
  if (position) attributes.set("data-position", position);
  return {
    getAttribute: name => attributes.get(name) ?? null,
    setAttribute: (name, value) => attributes.set(name, value),
    style: {
      getPropertyValue: name => styles.get(name) ?? "",
      setProperty: (name, value) => styles.set(name, value)
    }
  };
}

test("moves every floating HIP badge to the selected corner", () => {
  const first = badge("bottom-left");
  const second = badge("top-left");
  const documentObject = { querySelectorAll: () => [first, second] };

  assert.equal(placement.apply(documentObject, "bottom-right"), 2);
  assert.equal(first.getAttribute("data-position"), "bottom-right");
  assert.equal(second.getAttribute("data-position"), "bottom-right");
  assert.equal(first.style.getPropertyValue("--hip-overlap-shift"), "0px");
});

test("preserves publisher-owned inline badges", () => {
  const inline = badge("inline");
  const floating = badge("top-right");
  const documentObject = { querySelectorAll: () => [inline, floating] };

  assert.equal(placement.apply(documentObject, "top-left"), 1);
  assert.equal(inline.getAttribute("data-position"), "inline");
  assert.equal(floating.getAttribute("data-position"), "top-left");
});

test("normalizes invalid positions to the safe default", () => {
  const floating = badge();
  assert.equal(placement.apply({ querySelectorAll: () => [floating] }, "center"), 1);
  assert.equal(floating.getAttribute("data-position"), "bottom-left");
});
