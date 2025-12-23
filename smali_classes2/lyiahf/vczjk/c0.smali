.class public final Llyiahf/vczjk/c0;
.super Llyiahf/vczjk/dha;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/uv1;

.field public final OooO0OO:Llyiahf/vczjk/as7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uv1;Llyiahf/vczjk/as7;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/dha;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/c0;->OooO0O0:Llyiahf/vczjk/uv1;

    iput-object p2, p0, Llyiahf/vczjk/c0;->OooO0OO:Llyiahf/vczjk/as7;

    return-void
.end method


# virtual methods
.method public final OooO0Oo()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/c0;->OooO0O0:Llyiahf/vczjk/uv1;

    const-class v1, Llyiahf/vczjk/d0;

    invoke-static {v1, v0}, Llyiahf/vczjk/mc4;->OooOoo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/d0;

    check-cast v0, Llyiahf/vczjk/uv1;

    iget-object v0, v0, Llyiahf/vczjk/uv1;->OooO0OO:Llyiahf/vczjk/le7;

    invoke-interface {v0}, Llyiahf/vczjk/le7;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/zs7;

    invoke-virtual {v0}, Llyiahf/vczjk/zs7;->OooO00o()V

    return-void
.end method
