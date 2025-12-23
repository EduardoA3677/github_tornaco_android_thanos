.class public final synthetic Llyiahf/vczjk/n42;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/z23;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/l1a;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/l1a;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n42;->OooOOO0:Llyiahf/vczjk/l1a;

    return-void
.end method


# virtual methods
.method public final OooO00o()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n42;->OooOOO0:Llyiahf/vczjk/l1a;

    iget-object v0, v0, Llyiahf/vczjk/l1a;->OooOOo0:Llyiahf/vczjk/jx9;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/jx9;->getState()Llyiahf/vczjk/kx9;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/kx9;->OooO0O0()F

    move-result v0

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method
