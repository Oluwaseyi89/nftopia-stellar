import { render, fireEvent, screen } from "@testing-library/react";
import { Navbar } from "../components/navbar";
import PopularCollection from "../components/PopularCollection";
import { telemetry } from "../lib/telemetry";

jest.mock("../lib/telemetry", () => ({
  telemetry: { track: jest.fn() },
}));

describe("Navigation and CTA Telemetry Integration", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("emits nav_item_clicked when desktop nav link is clicked", () => {
    render(<Navbar />);
    // Simulate desktop viewport
    Object.defineProperty(window, "innerWidth", { writable: true, value: 1280 });
    window.dispatchEvent(new Event("resize"));
    // Find and click the 'Explore' nav link
    const exploreLink = screen.getAllByText(/explore/i)[0];
    fireEvent.click(exploreLink);
    expect(telemetry.track).toHaveBeenCalledWith(
      "nav_item_clicked",
      expect.objectContaining({ nav_item_id: "explore", placement: "navbar_desktop" })
    );
  });

  it("emits cta_clicked when PopularCollection Explore More is clicked", () => {
    render(<PopularCollection />);
    const exploreMore = screen.getByText(/explore more/i);
    fireEvent.click(exploreMore);
    expect(telemetry.track).toHaveBeenCalledWith(
      "cta_clicked",
      expect.objectContaining({ cta_id: "explore_more_popular_collection", placement: "landing_popular_collection_header" })
    );
  });
});
