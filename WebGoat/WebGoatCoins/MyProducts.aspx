<%@ Page Title="" Language="C#" ValidateRequest="false" MasterPageFile="~/Resources/Master-Pages/Site.Master" AutoEventWireup="true" CodeBehind="MyProducts.aspx.cs" Inherits="OWASP.WebGoat.NET.WebGoatCoins.MyProducts" %>
<asp:Content ID="Content1" ContentPlaceHolderID="HeadContentPlaceHolder" runat="server">
</asp:Content>
<asp:Content ID="Content2" ContentPlaceHolderID="HelpContentPlaceholder" runat="server">
</asp:Content>
<asp:Content ID="Content3" ContentPlaceHolderID="BodyContentPlaceholder" runat="server">
    
<script language="javascript" type="text/javascript">
        $(document).ready(function () {
            $("div.success").hide();
            setTimeout(function () {
                $("div.success").fadeIn("slow", function () {
                    $("div.success").show();
                });
            }, 500);
        });
 </script>

    <h1 class="title-regular-4 clearfix">My Products</h1>
        <div class="notice">
        <asp:Literal runat="server" EnableViewState="False" ID="labelMessage">
        View and manage your products. Select a product from the dropdown to see details and leave comments!
        </asp:Literal>
    </div>
    
    Select a product:<br />
    <asp:DropDownList ID="ddlItems" runat="server" 
        onselectedindexchanged="ddlItems_SelectedIndexChanged" 
        CausesValidation="True" AutoPostBack="True">
    </asp:DropDownList>

    <br />
    <asp:Button ID="Button1" runat="server" onclick="Button1_Click" Text="View Details" />
    <br />

    <asp:Label ID="lblMessage" runat="server">
    <div class="success">
    Comment Successfully Added!
    </div>
    </asp:Label>

    <h2 class='title-regular-2'>Leave a Comment</h2>
    
    <p>
        <asp:Table ID="Table1" runat="server" Width="100%">
            
            <asp:TableRow runat="server">
                <asp:TableCell runat="server" Width="10%">Email: </asp:TableCell>
                <asp:TableCell runat="server">
                    <asp:TextBox ID="txtEmail" runat="server" width="100%" CssClass="text"></asp:TextBox>
                </asp:TableCell>
            </asp:TableRow>
            
            <asp:TableRow runat="server">
                <asp:TableCell runat="server" Width="10%" VerticalAlign="Top" style="vertical-align:middle">
                    Comment:
                </asp:TableCell>
                <asp:TableCell runat="server">
                    <asp:TextBox ID="txtComment" runat="server" width="100%" Rows="5" TextMode="MultiLine" CssClass="text">
                    </asp:TextBox>
                </asp:TableCell>
            </asp:TableRow>
            
            <asp:TableRow runat="server">
                <asp:TableCell runat="server">&nbsp;</asp:TableCell>
                <asp:TableCell runat="server">
                    <asp:Button ID="btnSave" runat="server" Text="Save Comment" onclick="btnSave_Click" />
                </asp:TableCell>
            </asp:TableRow>

        </asp:Table>
    </p>
   
    <p />
    <a href="Catalog.aspx">Return to Catalog</a>
    <p />
    <asp:HiddenField ID="hiddenFieldProductID" runat="server" />

</asp:Content>