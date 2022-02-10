class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
  
  has_one_attached :avatar

  validates :name, :presence =>  true
  validates :email, :presence =>  true, :uniqueness => true
  validates :phone_number, :presence => false, :uniqueness => true, length: { minimum:10, maximum:15 }
  validates :avatar, :attached => false, size: { less_than: 2.megabytes , message: 'should not be more than 2 mb' }

end
