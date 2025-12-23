.class public final Llyiahf/vczjk/ny3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $this_animateValue:Llyiahf/vczjk/jy3;

.field final synthetic $transitionAnimation:Llyiahf/vczjk/dy3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/dy3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jy3;Llyiahf/vczjk/dy3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ny3;->$this_animateValue:Llyiahf/vczjk/jy3;

    iput-object p2, p0, Llyiahf/vczjk/ny3;->$transitionAnimation:Llyiahf/vczjk/dy3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/ny3;->$this_animateValue:Llyiahf/vczjk/jy3;

    iget-object v0, p0, Llyiahf/vczjk/ny3;->$transitionAnimation:Llyiahf/vczjk/dy3;

    iget-object v1, p1, Llyiahf/vczjk/jy3;->OooO00o:Llyiahf/vczjk/ws5;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/jy3;->OooO0O0:Llyiahf/vczjk/qs5;

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ny3;->$this_animateValue:Llyiahf/vczjk/jy3;

    iget-object v0, p0, Llyiahf/vczjk/ny3;->$transitionAnimation:Llyiahf/vczjk/dy3;

    new-instance v1, Llyiahf/vczjk/xb;

    const/4 v2, 0x4

    invoke-direct {v1, v2, p1, v0}, Llyiahf/vczjk/xb;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    return-object v1
.end method
