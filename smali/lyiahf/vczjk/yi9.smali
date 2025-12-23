.class public final Llyiahf/vczjk/yi9;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/p02;

.field public final OooO00o:Llyiahf/vczjk/lx4;

.field public final OooO0O0:Llyiahf/vczjk/mk9;

.field public final OooO0OO:Llyiahf/vczjk/gl9;

.field public final OooO0Oo:Z

.field public final OooO0o:Llyiahf/vczjk/fn9;

.field public final OooO0o0:Z

.field public final OooO0oO:Llyiahf/vczjk/s86;

.field public final OooO0oo:Llyiahf/vczjk/l8a;

.field public final OooOO0:Llyiahf/vczjk/e86;

.field public final OooOO0O:Llyiahf/vczjk/oe3;

.field public final OooOO0o:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;Llyiahf/vczjk/mk9;Llyiahf/vczjk/gl9;ZZLlyiahf/vczjk/fn9;Llyiahf/vczjk/s86;Llyiahf/vczjk/l8a;Llyiahf/vczjk/p02;Llyiahf/vczjk/oe3;I)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/dn8;->OooOOoo:Llyiahf/vczjk/e86;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/yi9;->OooO00o:Llyiahf/vczjk/lx4;

    iput-object p2, p0, Llyiahf/vczjk/yi9;->OooO0O0:Llyiahf/vczjk/mk9;

    iput-object p3, p0, Llyiahf/vczjk/yi9;->OooO0OO:Llyiahf/vczjk/gl9;

    iput-boolean p4, p0, Llyiahf/vczjk/yi9;->OooO0Oo:Z

    iput-boolean p5, p0, Llyiahf/vczjk/yi9;->OooO0o0:Z

    iput-object p6, p0, Llyiahf/vczjk/yi9;->OooO0o:Llyiahf/vczjk/fn9;

    iput-object p7, p0, Llyiahf/vczjk/yi9;->OooO0oO:Llyiahf/vczjk/s86;

    iput-object p8, p0, Llyiahf/vczjk/yi9;->OooO0oo:Llyiahf/vczjk/l8a;

    iput-object p9, p0, Llyiahf/vczjk/yi9;->OooO:Llyiahf/vczjk/p02;

    iput-object v0, p0, Llyiahf/vczjk/yi9;->OooOO0:Llyiahf/vczjk/e86;

    iput-object p10, p0, Llyiahf/vczjk/yi9;->OooOO0O:Llyiahf/vczjk/oe3;

    iput p11, p0, Llyiahf/vczjk/yi9;->OooOO0o:I

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/util/List;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/yi9;->OooO00o:Llyiahf/vczjk/lx4;

    iget-object v0, v0, Llyiahf/vczjk/lx4;->OooO0Oo:Llyiahf/vczjk/xk2;

    invoke-static {p1}, Llyiahf/vczjk/d21;->o0000OO0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/o13;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    const/4 v2, 0x0

    invoke-virtual {p1, v2, v1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xk2;->OooO00o(Ljava/util/List;)Llyiahf/vczjk/gl9;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/yi9;->OooOO0O:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method
