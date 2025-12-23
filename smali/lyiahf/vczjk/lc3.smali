.class public final Llyiahf/vczjk/lc3;
.super Llyiahf/vczjk/nc3;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/jf3;

.field public final synthetic OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

.field public final synthetic OooO0OO:Llyiahf/vczjk/m;

.field public final synthetic OooO0Oo:Llyiahf/vczjk/l;

.field public final synthetic OooO0o0:Landroidx/fragment/app/Oooo0;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/Oooo0;Llyiahf/vczjk/jf3;Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/m;Llyiahf/vczjk/l;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lc3;->OooO0o0:Landroidx/fragment/app/Oooo0;

    iput-object p2, p0, Llyiahf/vczjk/lc3;->OooO00o:Llyiahf/vczjk/jf3;

    iput-object p3, p0, Llyiahf/vczjk/lc3;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    iput-object p4, p0, Llyiahf/vczjk/lc3;->OooO0OO:Llyiahf/vczjk/m;

    iput-object p5, p0, Llyiahf/vczjk/lc3;->OooO0Oo:Llyiahf/vczjk/l;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/lc3;->OooO0o0:Landroidx/fragment/app/Oooo0;

    invoke-virtual {v0}, Landroidx/fragment/app/Oooo0;->generateActivityResultKey()Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/lc3;->OooO00o:Llyiahf/vczjk/jf3;

    const/4 v3, 0x0

    invoke-interface {v2, v3}, Llyiahf/vczjk/jf3;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/w;

    iget-object v3, p0, Llyiahf/vczjk/lc3;->OooO0OO:Llyiahf/vczjk/m;

    iget-object v4, p0, Llyiahf/vczjk/lc3;->OooO0Oo:Llyiahf/vczjk/l;

    invoke-virtual {v2, v1, v0, v3, v4}, Llyiahf/vczjk/w;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/uy4;Llyiahf/vczjk/m;Llyiahf/vczjk/l;)Llyiahf/vczjk/v;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/lc3;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    return-void
.end method
