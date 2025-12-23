.class public abstract Llyiahf/vczjk/z04;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nl5;
.implements Llyiahf/vczjk/rl5;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/s13;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/s13;-><init>(I)V

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/z04;->OooOOO0:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO0o(Llyiahf/vczjk/sl5;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/uoa;->OooO00o:Llyiahf/vczjk/ie7;

    invoke-interface {p1, v0}, Llyiahf/vczjk/sl5;->OooO0OO(Llyiahf/vczjk/ie7;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kna;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/z04;->OooOO0(Llyiahf/vczjk/kna;)Llyiahf/vczjk/kna;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/z04;->OooOOO0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0o0()Llyiahf/vczjk/kna;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z04;->OooOOO0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/kna;

    return-object v0
.end method

.method public abstract OooOO0(Llyiahf/vczjk/kna;)Llyiahf/vczjk/kna;
.end method

.method public final getKey()Llyiahf/vczjk/ie7;
    .locals 1

    sget-object v0, Llyiahf/vczjk/uoa;->OooO00o:Llyiahf/vczjk/ie7;

    return-object v0
.end method
