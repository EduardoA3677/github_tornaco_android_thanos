.class public Landroidx/versionedparcelable/ParcelImpl;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "BanParcelableUsage"
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Landroidx/versionedparcelable/ParcelImpl;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/bfa;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/k;

    const/16 v1, 0xe

    invoke-direct {v0, v1}, Llyiahf/vczjk/k;-><init>(I)V

    sput-object v0, Landroidx/versionedparcelable/ParcelImpl;->CREATOR:Landroid/os/Parcelable$Creator;

    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/afa;

    invoke-direct {v0, p1}, Llyiahf/vczjk/afa;-><init>(Landroid/os/Parcel;)V

    invoke-virtual {v0}, Llyiahf/vczjk/zea;->OooO0oO()Llyiahf/vczjk/bfa;

    move-result-object p1

    iput-object p1, p0, Landroidx/versionedparcelable/ParcelImpl;->OooOOO0:Llyiahf/vczjk/bfa;

    return-void
.end method


# virtual methods
.method public final describeContents()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 0

    new-instance p2, Llyiahf/vczjk/afa;

    invoke-direct {p2, p1}, Llyiahf/vczjk/afa;-><init>(Landroid/os/Parcel;)V

    iget-object p1, p0, Landroidx/versionedparcelable/ParcelImpl;->OooOOO0:Llyiahf/vczjk/bfa;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zea;->OooO(Llyiahf/vczjk/bfa;)V

    return-void
.end method
