.class public final Llyiahf/vczjk/xk9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $center:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xk9;->$center:Llyiahf/vczjk/le3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/f62;

    iget-object p1, p0, Llyiahf/vczjk/xk9;->$center:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p86;

    iget-wide v0, p1, Llyiahf/vczjk/p86;->OooO00o:J

    new-instance p1, Llyiahf/vczjk/p86;

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/p86;-><init>(J)V

    return-object p1
.end method
