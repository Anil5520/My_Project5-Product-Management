const userModel = require('../models/userModel')
const mongoose = require('mongoose')


const isValidRequestBody = function (requestBody) {
    return Object.keys(requestBody).length > 0;
};

const isValid = function (value) {
    if (typeof value === "undefined" || value === null) return false;
    if (typeof value === "string" && value.trim().length === 0) return false;
    return true;
};


//-------regex validation----------
let NameRegex = /^(?![\. ])[a-zA-Z\. ]+(?<! )$/
let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/
let passwordRegex = /^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[a-zA-Z!#$%&? "])[a-zA-Z0-9!#$%&?]{8,15}$/
let addressStreetRegex = /[^a-zA-Z0-9]/
let addressCityRegex = /^[a-zA-Z]+$/
let pincodeRegex = /^[1-9]\d{5}$/
let phoneRegex = /^[6-9]\d{9}$/

const updateData = async function (req, res) {
    try {
        let userId = req.params.userId
        let data = req.body
        let files = req.files

        let { fname, lname, email, phone, password, address } = data
        //-----------------------------VALIDATING USERID-----------------------------------------------------//
        if (!mongoose.isValidObjectId(userId)) return res.status(400).send({ status: false, msg: "Invalid UserId ..." })

        let checkUser = await userModel.findOne({ _id: userId })
        if (!checkUser) return res.status(404).send({ status: false, message: `This UserId: ${userId} doesn't exist` })

        //----------------------------AUTHORIZATION ----------------------------------------------------------//
        if (req.userId != checkUser._id)
            return res.status(401).send({ status: false, msg: "USER NOT AUTHORISED!!" })

        if (!isValidRequestBody(data)) {
            return res.status(400).send({ status: false, message: "Please provide valid requestBody" })
        }

        if (!data) return res.status(400).send({ status: false, message: "Data is not present in request body" })
        if (fname) {
            if (!isValid(fname) || !NameRegex.test(fname)) {
                return res.status(400).send({ status: false, message: "first name is not Valid" })
            } checkUser.fname = fname
        }
        if (lname) {
            if (!isValid(lname) || !NameRegex.test(lname)) {
                return res.status(400).send({ status: false, msg: "last name is not Valid" })
            } checkUser.lname = lname
        }
        if (email) {
            if (!isValid(email) || !emailRegex.test(email)) {
                return res.status(400).send({ status: false, msg: "email is not Valid" })
            }
            let uniqueEmail = await userModel.findOne({ email: email })
            if (uniqueEmail) {
                return res.status(409).send({ status: false, msg: "This email already exists, Please try another one." })
            } checkUser.email = email
        }
        if (files && files.length != 0) {
            let uploadedFileURL = await uploadFile(files[0])
            checkUser.profileImage = uploadedFileURL
        }
        if (phone) {
            if (!isValid(phone) || !phoneRegex.test(phone)) {
                return res.status(400).send({ status: false, msg: "Phone no is not Valid" })
            }
            let uniquePhone = await userModel.findOne({ phone: phone })
            if (uniquePhone) {
                return res.status(409).send({ status: false, message: "This phone number already exists, Please try another one." })
            } checkUser.phone = phone
        }

        //--------------------------------UPDATING BCRYPTED PASSWORD------------------------------------------//
        if (password) {
            if (passwordRegex.test(password)) {
                let saltRounds = await bcrypt.genSalt(10)
                password = await bcrypt.hash(password, saltRounds)
            }
            else {
                return res.status(400).send({ status: false, message: "password should be strong please use One digit, one upper case , one lower case ,one special character, its b/w 8 to 15" })
            }
        }

        //------------------------------ADDRESS VALIDATION FOR UPDATING---------------------------------------//
        if (address) {
            if (Object.keys(address).length == 0) return res.status(400).send({ status: false, message: "Please enter address and it should be in object!!" })
            address = JSON.parse(address)

            if (address.shipping.street) {
                if (!addressStreetRegex.test(address.shipping.street)) {
                    return res.status(400).send({ status: false, message: "Invalid Shipping street" })
                }
            } checkUser.address.shipping.street= address.shipping.street

            if (address.shipping.city) {
                if (!addressCityRegex.test(address.shipping.city)) {
                    return res.status(400).send({ status: false, message: "Invalid Shipping city" })
                }
            } checkUser.address.shipping.city= address.shipping.city

            if (address.shipping.pincode) {
                if (!pincodeRegex.test(address.shipping.pincode)) {
                    return res.status(400).send({ status: false, message: "Invalid Shipping pincode" })
                }
            } checkUser.address.shipping.pincode= address.shipping.pincode

            if (address.billing.street) {
                if (!addressStreetRegex.test(address.billing.street)) {
                    return res.status(400).send({ status: false, message: "Invalid billing street" })
                }
            } checkUser.address.billing.street= address.billing.street

            if (address.billing.city) {
                if (!addressCityRegex.test(address.billing.city)) {
                    return res.status(400).send({ status: false, message: "Invalid billing city" })
                }
            } checkUser.address.billing.city= address.billing.city

            if (address.billing.pincode) {
                if (!pincodeRegex.test(address.billing.pincode)) {
                    return res.status(400).send({ status: false, message: "Invalid Billing pincode" })
                }
            } checkUser.address.billing.pincode= address.billing.pincode
        }
        checkUser.save()
        res.status(200).send({ status: true, message: "User profile details", data: checkUser })
    }
    catch (error) {
        console.log(error)
        res.status(500).send({ status: false, message: error.message })
    }
}