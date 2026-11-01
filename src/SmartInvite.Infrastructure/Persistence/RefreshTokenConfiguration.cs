using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SmartInvite.Infrastructure.Identity;

namespace SmartInvite.Infrastructure.Persistence;

public sealed class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("RefreshTokens");

        builder.HasKey(t => t.Id);

        builder.Property(t => t.Id)
            .ValueGeneratedNever();

        builder.Property(t => t.UserId)
            .IsRequired();

        builder.Property(t => t.TokenHash)
            .IsRequired()
            .HasMaxLength(RefreshToken.TokenHashLength)
            .IsUnicode(false)
            .IsFixedLength();

        builder.Property(t => t.FamilyId)
            .IsRequired();

        builder.Property(t => t.CreatedAt)
            .IsRequired();

        builder.Property(t => t.ExpiresAt)
            .IsRequired();

        builder.Property(t => t.RotatedAt);

        builder.Property(t => t.RevokedAt);

        builder.Property(t => t.ReplacedByTokenId);

        builder.Property(t => t.RevokedReason)
            .HasMaxLength(RefreshToken.MaxRevokedReasonLength);

        builder.Ignore(t => t.IsRotated);
        builder.Ignore(t => t.IsRevoked);

        builder.HasOne<ApplicationUser>()
            .WithMany()
            .HasForeignKey(t => t.UserId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired();

        builder.HasIndex(t => t.TokenHash)
            .HasDatabaseName("IX_RefreshTokens_TokenHash")
            .IsUnique();

        builder.HasIndex(t => t.UserId)
            .HasDatabaseName("IX_RefreshTokens_UserId");

        builder.HasIndex(t => t.FamilyId)
            .HasDatabaseName("IX_RefreshTokens_FamilyId");

        builder.HasIndex(t => t.ExpiresAt)
            .HasDatabaseName("IX_RefreshTokens_ExpiresAt");
    }
}

