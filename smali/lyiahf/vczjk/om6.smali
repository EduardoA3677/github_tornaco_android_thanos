.class public final Llyiahf/vczjk/om6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $initialPage:I


# direct methods
.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/om6;->$initialPage:I

    invoke-direct {p0, v0}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/km6;

    iget v1, p0, Llyiahf/vczjk/om6;->$initialPage:I

    invoke-direct {v0, v1}, Llyiahf/vczjk/km6;-><init>(I)V

    return-object v0
.end method
