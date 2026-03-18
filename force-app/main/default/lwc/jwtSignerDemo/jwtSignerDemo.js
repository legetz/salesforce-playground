import { LightningElement, track } from "lwc";
import generateJwt from "@salesforce/apex/JwtSignerService.generateJwt";

export default class JwtSignerDemo extends LightningElement {
  @track response;
  @track errorMessage;
  isLoading = false;

  get hasResponse() {
    return !!this.response;
  }

  get issuedAtLabel() {
    return this.formatEpochSeconds(this.response?.issuedAtEpochSeconds);
  }

  get expiresAtLabel() {
    return this.formatEpochSeconds(this.response?.expiresAtEpochSeconds);
  }

  async handleGenerateClick() {
    this.isLoading = true;
    this.errorMessage = undefined;
    this.response = undefined;

    try {
      this.response = await generateJwt();
    } catch (error) {
      this.errorMessage =
        error?.body?.message || error?.message || "JWT generation failed.";
    } finally {
      this.isLoading = false;
    }
  }

  formatEpochSeconds(epochSeconds) {
    if (epochSeconds === undefined || epochSeconds === null) {
      return "";
    }

    return new Date(epochSeconds * 1000).toLocaleString();
  }
}
