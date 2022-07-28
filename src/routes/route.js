const express = require('express');
const router = express.Router();
const { authentication, authorization } = require('../middlewares/auth')
const { createUser, userLogin, getUser, updateData } = require('../controllers/userController');
const { createProduct, getproduct, getProductById, deleteProduct } = require('../controllers/productController');


router.post('/register', createUser)
router.post('/login', userLogin)
router.get('/user/:userId/profile', authentication, authorization, getUser)
router.put('/user/:userId/profile', authentication, authorization, updateData)

router.post('/products', createProduct)
router.get('/products', getproduct)
router.get('/products/:productId', getProductById)
// router.put('/products/:productId', updateProductById)
router.delete('/products/:productId', deleteProduct)




router.all('/*', function (req, res) {
    res.status(400).send({ status: false, message: "Invalid params" })
})


module.exports = router; 