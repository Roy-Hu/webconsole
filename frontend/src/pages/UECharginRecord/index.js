import React, { Component } from "react";
import { Button } from "react-bootstrap";
import { Link, withRouter } from "react-router-dom";
import { BootstrapTable, TableHeaderColumn } from "react-bootstrap-table";
import { connect } from "react-redux";
import UEInfoApiHelper from "../../util/UEInfoApiHelper";

class DetailButton extends Component {
  handleClick = (cell) => {
    UEInfoApiHelper.fetchUEInfoDetail(cell).then((result) => {
      let success = result[0];
      let smContextRef = result[1];

      if (success) {
        UEInfoApiHelper.fetchUEInfoDetailSMF(smContextRef).then();
      }
    });
  };

  render() {
    const { cell } = this.props;
    return (
      <Button bsStyle="primary" onClick={this.handleClick(cell)}>
        <Link to={`/ueinfo/${cell}`}>Show Info</Link>
      </Button>
    );
  }
}

class UECharginRecord extends Component {
  componentDidMount() {
    UEInfoApiHelper.fetchUEWithCR().then();

    this.interval = setInterval(async () => {
      await UEInfoApiHelper.fetchUEWithCR();
    }, 1000);
  }

  componentWillUnmount() {
    clearInterval(this.interval);
  }

  cellButton = (cell, row, _, rowIndex) => {
    return <DetailButton cell={cell} row={row} rowIndex={rowIndex} />;
  };

  render() {
    return (
      <div className="content">
        <div className="container-fluid">
          <div className="dashboard__title">
            <h2>Real Time Status with Charging Record</h2>
            <Button
              bsStyle={"primary"}
              className="subscribers__button"
              onClick={() => UEInfoApiHelper.fetchUEWithCR().then()}
            >
              Refresh
            </Button>
          </div>
          <div className="row">
            <div className="col-12">
              {!this.props.get_ue_cr_err && (
                <BootstrapTable
                  data={this.props.users_cr}
                  striped={true}
                  hover={true}
                  pagination={true}
                >
                  <TableHeaderColumn
                    dataField="supi"
                    width="15%"
                    isKey={true}
                    dataAlign="center"
                    dataSort={true}
                  >
                    SUPI
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="status"
                    width="8%"
                    dataSort={true}
                  >
                    Status
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="supi"
                    width="8%"
                    dataFormat={this.cellButton}
                  >
                    Details
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="quotaLeft"
                    width="13%"
                    dataSort={true}
                  >
                    Quota Left
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="totalVol"
                    width="14%"
                    dataSort={true}
                  >
                    Data Total Volume &#40;KB&#41;{" "}
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="ulVol"
                    width="14%"
                    dataSort={true}
                  >
                    Data Volume Uplink &#40;KB&#41;
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="dlVol"
                    width="14%"
                    dataSort={true}
                  >
                    Data Volume Downlink &#40;KB&#41;
                  </TableHeaderColumn>
                </BootstrapTable>
              )}
            </div>
            <div className="col-12">
              {this.props.get_ue_cr_err && <h2>{this.props.ue_cr_err_msg}</h2>}
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default withRouter(
  connect((state) => ({
    users_cr: state.ueinfo.users_cr,
    get_ue_cr_err: state.ueinfo.get_ue_cr_err,
    ue_cr_err_msg: state.ueinfo.ue_cr_err_msg,
    smContextRef: state.ueinfo.smContextRef,
  }))(UECharginRecord)
);
