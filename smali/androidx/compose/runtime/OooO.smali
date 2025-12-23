.class public abstract Landroidx/compose/runtime/OooO;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/xw4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/xw4;

    invoke-direct {v0, p1}, Llyiahf/vczjk/xw4;-><init>(Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Landroidx/compose/runtime/OooO;->OooO00o:Llyiahf/vczjk/xw4;

    return-void
.end method


# virtual methods
.method public abstract OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;
.end method

.method public OooO0O0()Llyiahf/vczjk/ica;
    .locals 1

    iget-object v0, p0, Landroidx/compose/runtime/OooO;->OooO00o:Llyiahf/vczjk/xw4;

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ica;)Llyiahf/vczjk/ica;
    .locals 3

    instance-of v0, p2, Llyiahf/vczjk/gk2;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    iget-boolean v0, p1, Llyiahf/vczjk/ke7;->OooO0Oo:Z

    if-eqz v0, :cond_3

    move-object v1, p2

    check-cast v1, Llyiahf/vczjk/gk2;

    iget-object p2, v1, Llyiahf/vczjk/gk2;->OooO00o:Llyiahf/vczjk/qs5;

    invoke-virtual {p1}, Llyiahf/vczjk/ke7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast p2, Llyiahf/vczjk/fw8;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    instance-of v0, p2, Llyiahf/vczjk/o39;

    if-eqz v0, :cond_2

    iget-boolean v0, p1, Llyiahf/vczjk/ke7;->OooO0O0:Z

    if-nez v0, :cond_1

    iget-object v0, p1, Llyiahf/vczjk/ke7;->OooO0o0:Ljava/lang/Object;

    if-eqz v0, :cond_3

    :cond_1
    iget-boolean v0, p1, Llyiahf/vczjk/ke7;->OooO0Oo:Z

    if-nez v0, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/ke7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast p2, Llyiahf/vczjk/o39;

    iget-object v2, p2, Llyiahf/vczjk/o39;->OooO00o:Ljava/lang/Object;

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_3

    move-object v1, p2

    goto :goto_0

    :cond_2
    instance-of v0, p2, Llyiahf/vczjk/kh1;

    if-eqz v0, :cond_3

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    check-cast p2, Llyiahf/vczjk/kh1;

    iget-object p2, p2, Llyiahf/vczjk/kh1;->OooO00o:Llyiahf/vczjk/rm4;

    :cond_3
    :goto_0
    if-nez v1, :cond_6

    iget-boolean p2, p1, Llyiahf/vczjk/ke7;->OooO0Oo:Z

    if-eqz p2, :cond_5

    new-instance p2, Llyiahf/vczjk/gk2;

    iget-object v0, p1, Llyiahf/vczjk/ke7;->OooO0OO:Llyiahf/vczjk/gw8;

    if-nez v0, :cond_4

    sget-object v0, Llyiahf/vczjk/rp3;->OooOo0O:Llyiahf/vczjk/rp3;

    :cond_4
    new-instance v1, Landroidx/compose/runtime/ParcelableSnapshotMutableState;

    iget-object p1, p1, Llyiahf/vczjk/ke7;->OooO0o0:Ljava/lang/Object;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/fw8;-><init>(Ljava/lang/Object;Llyiahf/vczjk/gw8;)V

    invoke-direct {p2, v1}, Llyiahf/vczjk/gk2;-><init>(Llyiahf/vczjk/qs5;)V

    return-object p2

    :cond_5
    new-instance p2, Llyiahf/vczjk/o39;

    invoke-virtual {p1}, Llyiahf/vczjk/ke7;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    invoke-direct {p2, p1}, Llyiahf/vczjk/o39;-><init>(Ljava/lang/Object;)V

    return-object p2

    :cond_6
    return-object v1
.end method
