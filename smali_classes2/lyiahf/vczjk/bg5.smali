.class public final Llyiahf/vczjk/bg5;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/yd7;

.field public final OooOOO0:Llyiahf/vczjk/cg5;

.field public final OooOOOO:Llyiahf/vczjk/sg3;

.field public final OooOOOo:I

.field public final OooOOo:Llyiahf/vczjk/pd7;

.field public final OooOOo0:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cg5;Llyiahf/vczjk/yd7;Llyiahf/vczjk/sg3;IILlyiahf/vczjk/pd7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bg5;->OooOOO0:Llyiahf/vczjk/cg5;

    iput-object p2, p0, Llyiahf/vczjk/bg5;->OooOOO:Llyiahf/vczjk/yd7;

    iput-object p3, p0, Llyiahf/vczjk/bg5;->OooOOOO:Llyiahf/vczjk/sg3;

    iput p4, p0, Llyiahf/vczjk/bg5;->OooOOOo:I

    iput p5, p0, Llyiahf/vczjk/bg5;->OooOOo0:I

    iput-object p6, p0, Llyiahf/vczjk/bg5;->OooOOo:Llyiahf/vczjk/pd7;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/bg5;->OooOOO0:Llyiahf/vczjk/cg5;

    iget-object v0, v0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v1, v0, Llyiahf/vczjk/s72;->OooO0o0:Llyiahf/vczjk/hn;

    iget-object v2, p0, Llyiahf/vczjk/bg5;->OooOOO:Llyiahf/vczjk/yd7;

    iget-object v6, p0, Llyiahf/vczjk/bg5;->OooOOo:Llyiahf/vczjk/pd7;

    iget-object v3, p0, Llyiahf/vczjk/bg5;->OooOOOO:Llyiahf/vczjk/sg3;

    iget v4, p0, Llyiahf/vczjk/bg5;->OooOOOo:I

    iget v5, p0, Llyiahf/vczjk/bg5;->OooOOo0:I

    invoke-interface/range {v1 .. v6}, Llyiahf/vczjk/zn;->OooOO0o(Llyiahf/vczjk/yd7;Llyiahf/vczjk/sg3;IILlyiahf/vczjk/pd7;)Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method
