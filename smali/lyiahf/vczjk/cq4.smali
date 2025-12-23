.class public final Llyiahf/vczjk/cq4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $latestContent:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cq4;->$latestContent:Llyiahf/vczjk/p29;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/zp4;

    iget-object v1, p0, Llyiahf/vczjk/cq4;->$latestContent:Llyiahf/vczjk/p29;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-direct {v0, v1}, Llyiahf/vczjk/zp4;-><init>(Llyiahf/vczjk/oe3;)V

    return-object v0
.end method
