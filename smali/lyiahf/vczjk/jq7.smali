.class public final Llyiahf/vczjk/jq7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sy4;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/hl7;

.field public final synthetic OooOOO0:Llyiahf/vczjk/iy4;

.field public final synthetic OooOOOO:Llyiahf/vczjk/xr1;

.field public final synthetic OooOOOo:Llyiahf/vczjk/iy4;

.field public final synthetic OooOOo:Llyiahf/vczjk/mt5;

.field public final synthetic OooOOo0:Llyiahf/vczjk/yp0;

.field public final synthetic OooOOoo:Llyiahf/vczjk/ze3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/iy4;Llyiahf/vczjk/hl7;Llyiahf/vczjk/xr1;Llyiahf/vczjk/iy4;Llyiahf/vczjk/yp0;Llyiahf/vczjk/mt5;Llyiahf/vczjk/ze3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/jq7;->OooOOO0:Llyiahf/vczjk/iy4;

    iput-object p2, p0, Llyiahf/vczjk/jq7;->OooOOO:Llyiahf/vczjk/hl7;

    iput-object p3, p0, Llyiahf/vczjk/jq7;->OooOOOO:Llyiahf/vczjk/xr1;

    iput-object p4, p0, Llyiahf/vczjk/jq7;->OooOOOo:Llyiahf/vczjk/iy4;

    iput-object p5, p0, Llyiahf/vczjk/jq7;->OooOOo0:Llyiahf/vczjk/yp0;

    iput-object p6, p0, Llyiahf/vczjk/jq7;->OooOOo:Llyiahf/vczjk/mt5;

    iput-object p7, p0, Llyiahf/vczjk/jq7;->OooOOoo:Llyiahf/vczjk/ze3;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V
    .locals 3

    iget-object p1, p0, Llyiahf/vczjk/jq7;->OooOOO:Llyiahf/vczjk/hl7;

    iget-object v0, p0, Llyiahf/vczjk/jq7;->OooOOO0:Llyiahf/vczjk/iy4;

    const/4 v1, 0x0

    if-ne p2, v0, :cond_0

    new-instance p2, Llyiahf/vczjk/iq7;

    iget-object v0, p0, Llyiahf/vczjk/jq7;->OooOOo:Llyiahf/vczjk/mt5;

    iget-object v2, p0, Llyiahf/vczjk/jq7;->OooOOoo:Llyiahf/vczjk/ze3;

    invoke-direct {p2, v0, v2, v1}, Llyiahf/vczjk/iq7;-><init>(Llyiahf/vczjk/jt5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    iget-object v2, p0, Llyiahf/vczjk/jq7;->OooOOOO:Llyiahf/vczjk/xr1;

    invoke-static {v2, v1, v1, p2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p2

    iput-object p2, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/jq7;->OooOOOo:Llyiahf/vczjk/iy4;

    if-ne p2, v0, :cond_2

    iget-object v0, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v74;

    if-eqz v0, :cond_1

    invoke-interface {v0, v1}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_1
    iput-object v1, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    :cond_2
    sget-object p1, Llyiahf/vczjk/iy4;->ON_DESTROY:Llyiahf/vczjk/iy4;

    if-ne p2, p1, :cond_3

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object p2, p0, Llyiahf/vczjk/jq7;->OooOOo0:Llyiahf/vczjk/yp0;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    :cond_3
    return-void
.end method
