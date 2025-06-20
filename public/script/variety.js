var module = angular.module("myModule", []);

module.controller("myController", function ($scope, $http) {

    $scope.jsonArray = [];
    $scope.selObj = {};  // Initialize selObj
    $scope.selObj1 = {};

    // Fetch all records for the active user
    $scope.fetchRecords = function () {
        const sc = localStorage.getItem("Active_subcategory");
        const c = localStorage.getItem("Active_category");
        $scope.selObj.txtsubCategory = sc;
        $scope.selObj1.txtCategory = c;

        // Create the URL with the email appended as a query parameter
        const url = `/get-angular-variety-records?sub_category=${encodeURIComponent($scope.selObj.txtsubCategory)}&category=${$scope.selObj1.txtCategory}`;

        // Make the GET request
        $http.get(url).then(
            function done(response) {
                if (response.data.message === "No products with this Category") {
                    if (!$scope.alertShown) {  // ✅ Prevent duplicate alerts
                        alert("No products with this Category");
                        $scope.alertShown = true; 
                    }
                    $scope.jsonArray = []; // Clear the array to reflect no products
                } else {
                    $scope.jsonArray = response.data;
                    $scope.alertShown = false; // Reset alert flag when data is found
                }
            },
            function fail(response) {
                console.error("Error fetching records:", response.data);
                alert("Failed to fetch records. Please try again.");
            }
        );
        
    };

    // Define showProduct function inside the controller
    $scope.showProduct = function (productID) {
        localStorage.setItem("Active_Product", productID);
        location.href = "product.html";
    };

    // Initial fetch of records on controller load
    $scope.fetchRecords();
});
