.class public final Llyiahf/vczjk/sp1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $imeOptions:Llyiahf/vczjk/wv3;

.field final synthetic $state:Llyiahf/vczjk/lx4;

.field final synthetic $textInputService:Llyiahf/vczjk/tl9;

.field final synthetic $value:Llyiahf/vczjk/gl9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;Llyiahf/vczjk/tl9;Llyiahf/vczjk/gl9;Llyiahf/vczjk/wv3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sp1;->$state:Llyiahf/vczjk/lx4;

    iput-object p2, p0, Llyiahf/vczjk/sp1;->$textInputService:Llyiahf/vczjk/tl9;

    iput-object p3, p0, Llyiahf/vczjk/sp1;->$value:Llyiahf/vczjk/gl9;

    iput-object p4, p0, Llyiahf/vczjk/sp1;->$imeOptions:Llyiahf/vczjk/wv3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/sp1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {p1}, Llyiahf/vczjk/lx4;->OooO0O0()Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/sp1;->$state:Llyiahf/vczjk/lx4;

    iget-object v0, p0, Llyiahf/vczjk/sp1;->$textInputService:Llyiahf/vczjk/tl9;

    iget-object v1, p0, Llyiahf/vczjk/sp1;->$value:Llyiahf/vczjk/gl9;

    iget-object v2, p1, Llyiahf/vczjk/lx4;->OooO0Oo:Llyiahf/vczjk/xk2;

    iget-object v3, p0, Llyiahf/vczjk/sp1;->$imeOptions:Llyiahf/vczjk/wv3;

    new-instance v4, Llyiahf/vczjk/hl7;

    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    new-instance v5, Llyiahf/vczjk/mi9;

    iget-object v6, p1, Llyiahf/vczjk/lx4;->OooOo0O:Llyiahf/vczjk/kx4;

    invoke-direct {v5, v2, v6, v4}, Llyiahf/vczjk/mi9;-><init>(Llyiahf/vczjk/xk2;Llyiahf/vczjk/kx4;Llyiahf/vczjk/hl7;)V

    iget-object v2, v0, Llyiahf/vczjk/tl9;->OooO00o:Llyiahf/vczjk/tx6;

    iget-object v6, p1, Llyiahf/vczjk/lx4;->OooOo0o:Llyiahf/vczjk/jx4;

    invoke-interface {v2, v1, v3, v5, v6}, Llyiahf/vczjk/tx6;->OooO0oo(Llyiahf/vczjk/gl9;Llyiahf/vczjk/wv3;Llyiahf/vczjk/mi9;Llyiahf/vczjk/jx4;)V

    new-instance v1, Llyiahf/vczjk/yl9;

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/yl9;-><init>(Llyiahf/vczjk/tl9;Llyiahf/vczjk/tx6;)V

    iget-object v0, v0, Llyiahf/vczjk/tl9;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    iput-object v1, v4, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    iput-object v1, p1, Llyiahf/vczjk/lx4;->OooO0o0:Llyiahf/vczjk/yl9;

    :cond_0
    new-instance p1, Llyiahf/vczjk/ef;

    const/4 v0, 0x1

    invoke-direct {p1, v0}, Llyiahf/vczjk/ef;-><init>(I)V

    return-object p1
.end method
