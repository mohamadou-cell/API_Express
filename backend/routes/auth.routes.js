const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const router = express.Router()
const userSchema = require('../models/User')
const authorize = require('../middlewares/auth')
const { check, validationResult } = require('express-validator')
mongoose = require('mongoose')
multer = require('multer')

// Paramètres de téléchargement de fichiers Multer
const DIR = './images/'

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, DIR)
  },
  filename: (req, file, cb) => {
    const fileName = file.originalname.toLowerCase().split(' ').join('-')
    cb(null, fileName)
  },
})

// Validation du type mime de Multer
var upload = multer({
  storage: storage,
  limits: {
    fileSize: 1024 * 1024 * 5,
  },
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype == 'image/png' ||
      file.mimetype == 'image/jpg' ||
      file.mimetype == 'image/jpeg'
    ) {
      cb(null, true)
    } else {
      cb(null, false)
      return cb(new Error('Seulement, les formats .png, .jpg and .jpeg sont autorisés!'))
    }
  },
})

// Inscription
router.post(
  '/register-user', upload.single('imageUrl'),
  [
    check('nom').not().isEmpty(),
    check('prenom').not().isEmpty(),
    check('email', 'Email is required').not().isEmpty(),
    check('password', 'Password should be between 8 to 16 characters long')
      .not()
      .isEmpty()
      .isLength({ min: 8, max: 16 }),
  ],
  authorize,(req, res, next) => {
    const errors = validationResult(req)
    console.log(req.body)

      bcrypt.hash(req.body.password, 10).then((hash) => {

        const url = req.protocol + '://' + req.get('host')
        const user = new userSchema({
          prenom: req.body.prenom,
          nom: req.body.nom,
          email: req.body.email,
          role: req.body.role,
          password: hash,
          etat: req.body.etat,
          imageUrl: url + '/images/' + req.file?.filename,
          matricule: req.body.matricule,
        })
        user
          .save()
          .then((response) => {
            console.log(response);
            res.status(201).json({
              message: 'Inscription réussie !',
              result: response,
            })
          })
          .catch((error) => {
            res.status(409).json({
              error: error.message.split("email:")[1],
            })
          })
      })
  },
)


// Connection
router.post('/signin', async (req, res, next) => {
  let getUser
  userSchema
    .findOne({
      email: req.body.email,
    })
    .then((user) => {
      if (!user) {
        return res.status(401).json({
          message: 'Compte non existant !',
        })
      }
      getUser = user
      return bcrypt.compareSync(req.body.password, user.password)
    })
    .then((response) => {
      if (!response) {
        return res.status(401).json({
          message: 'Le mot de passe est incorrect !',
        })
      }else if(getUser.etat == true){
        return res.status(401).json({
          message: 'Le compte est désactivé !' ,
        })
      }
      let jwtToken = jwt.sign(
        {
          email: getUser.email,
          userId: getUser._id,
        },
        'longer-secret-is-better',
        {
          expiresIn: '1h',
        },
      )
      res.status(200).json({
        token: jwtToken,
        expiresIn: 3600,
        _id: getUser._id,
      })
    })
    .catch((err) => {
      return res.status(401).json({
        message: 'Authentification échouée',
      })
    })
})

// Récupérer les données de tous les utilisateurs
router.route('/').get(authorize,(req, res, next) => {
  userSchema.find((error, response)=> {
    if (error) {
      return next(error)
    } else {
      return res.status(200).json(response)
    }
  })
})


// Récupérer les données d'un utilisateur 
router.route('/read-user/:id').get(authorize,(req, res) => {
  userSchema.findById(req.params.id, (error, data) => {
    if (error) {
      return next(error);
    } else {
      res.json(data);
    }
  });
});




// Récupérer les données d'un utilisateur avec token
router.route('/user-profile/:id').get(authorize,(req, res, next) => {
  userSchema.findById(req.params.id, (error, data) => {
    if (error) {
      return next(error)
    } else {
      res.status(200).json({
        msg: data,
      })
    }
  })
})

// Modifier un utilisateur
router.route('/update-user/:id').put(authorize, (req, res, next) => {
  console.log(req.body)
  userSchema.findByIdAndUpdate(
    req.params.id,
    {
      $set: req.body,
    },
    (error, data) => {
      if (error) {
        return next(error)
      } else {
        res.status(200).json({msg: data,})
        console.log('Modification réussie !')
      }
    },
  )
})

// Modification mot de passe
router.route('/update/:id').put(authorize, async(req, res) => {
  try {
  const id = req.params.id;
  const updatedData = req.body;
  const options = { new: true };
  
      updatedData.password
      const hash = await bcrypt.hash(updatedData.password, 10);
      updatedData.password = hash;
      
              const result = await userSchema.findByIdAndUpdate(
              id, updatedData, options);
            return  res.send(result);        
  }
  catch (error) {
      res.status(400).json({ message: error.message })
  }
  })

// Supprimer un utilisateur
router.route('/delete-user/:id').delete(authorize, (req, res, next) => {
  userSchema.findByIdAndRemove(req.params.id, (error, data) => {
    if (error) {
      return next(error)
    } else {
      res.status(200).json({
        msg: data,
      })
      console.log('Suppression réussie !')
    }
  })
})

module.exports = router
