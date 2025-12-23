.class public final Llyiahf/vczjk/ed8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/lang/Object;

.field public final OooO0O0:Llyiahf/vczjk/wf3;

.field public final OooO0OO:Llyiahf/vczjk/bf3;

.field public final OooO0Oo:Llyiahf/vczjk/h87;

.field public OooO0o:Ljava/lang/Object;

.field public final OooO0o0:Llyiahf/vczjk/eb9;

.field public OooO0oO:I

.field public final synthetic OooO0oo:Llyiahf/vczjk/gd8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gd8;Ljava/lang/Object;Llyiahf/vczjk/bf3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/h87;Llyiahf/vczjk/eb9;Llyiahf/vczjk/dj0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ed8;->OooO0oo:Llyiahf/vczjk/gd8;

    iput-object p2, p0, Llyiahf/vczjk/ed8;->OooO00o:Ljava/lang/Object;

    check-cast p3, Llyiahf/vczjk/wf3;

    iput-object p3, p0, Llyiahf/vczjk/ed8;->OooO0O0:Llyiahf/vczjk/wf3;

    iput-object p4, p0, Llyiahf/vczjk/ed8;->OooO0OO:Llyiahf/vczjk/bf3;

    iput-object p5, p0, Llyiahf/vczjk/ed8;->OooO0Oo:Llyiahf/vczjk/h87;

    iput-object p6, p0, Llyiahf/vczjk/ed8;->OooO0o0:Llyiahf/vczjk/eb9;

    const/4 p1, -0x1

    iput p1, p0, Llyiahf/vczjk/ed8;->OooO0oO:I

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ed8;->OooO0o:Ljava/lang/Object;

    instance-of v1, v0, Llyiahf/vczjk/zc8;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/zc8;

    iget v1, p0, Llyiahf/vczjk/ed8;->OooO0oO:I

    iget-object v2, p0, Llyiahf/vczjk/ed8;->OooO0oo:Llyiahf/vczjk/gd8;

    iget-object v2, v2, Llyiahf/vczjk/gd8;->OooOOO0:Llyiahf/vczjk/or1;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/zc8;->OooO0oo(ILlyiahf/vczjk/or1;)V

    return-void

    :cond_0
    instance-of v1, v0, Llyiahf/vczjk/sc2;

    if-eqz v1, :cond_1

    check-cast v0, Llyiahf/vczjk/sc2;

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_2

    invoke-interface {v0}, Llyiahf/vczjk/sc2;->OooO00o()V

    :cond_2
    return-void
.end method
