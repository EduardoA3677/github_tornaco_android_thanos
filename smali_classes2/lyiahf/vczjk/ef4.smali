.class public final Llyiahf/vczjk/ef4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:I

.field public final OooOOO0:Llyiahf/vczjk/eo0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eo0;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ef4;->OooOOO0:Llyiahf/vczjk/eo0;

    iput p2, p0, Llyiahf/vczjk/ef4;->OooOOO:I

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ef4;->OooOOO0:Llyiahf/vczjk/eo0;

    invoke-interface {v0}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/ef4;->OooOOO:I

    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v1, "get(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/ko6;

    return-object v0
.end method
