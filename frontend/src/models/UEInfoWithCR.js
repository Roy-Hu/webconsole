export default class UEInfoWithCR {
  
    supi = "";
    status = "";
    totalVol = 0;
    ulVol = 0;
    dlVol = 0;

    constructor(supi, status, totalVol=0, ulVol=0, dlVol=0) {
      this.supi = supi;
      this.status = status;
      this.totalVol = totalVol;
      this.ulVol = ulVol;
      this.dlVol = dlVol;
    }

    // constructor(supi, status) {
    //   this.supi = supi;
    //   this.status = status;
    // }
  }