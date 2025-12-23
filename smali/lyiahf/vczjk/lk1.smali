.class public abstract Llyiahf/vczjk/lk1;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-string v0, "ConstraintTrkngWrkr"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "tagWithPrefix(\"ConstraintTrkngWrkr\")"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/lk1;->OooO00o:Ljava/lang/String;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/aqa;Llyiahf/vczjk/ara;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p2, Llyiahf/vczjk/jk1;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/jk1;

    iget v1, v0, Llyiahf/vczjk/jk1;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/jk1;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/jk1;

    invoke-direct {v0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/jk1;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/jk1;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/aqa;->OooO0O0(Llyiahf/vczjk/ara;)Llyiahf/vczjk/f43;

    move-result-object p0

    new-instance p2, Llyiahf/vczjk/kk1;

    const/4 v2, 0x0

    invoke-direct {p2, p1, v2}, Llyiahf/vczjk/kk1;-><init>(Llyiahf/vczjk/ara;Llyiahf/vczjk/yo1;)V

    new-instance p1, Llyiahf/vczjk/w53;

    const/4 v2, 0x1

    invoke-direct {p1, p0, p2, v2}, Llyiahf/vczjk/w53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;I)V

    new-instance p0, Llyiahf/vczjk/ve1;

    const/4 p2, 0x1

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ve1;-><init>(Llyiahf/vczjk/w53;I)V

    iput v3, v0, Llyiahf/vczjk/jk1;->label:I

    invoke-static {p0, v0}, Llyiahf/vczjk/rs;->OooOoO(Llyiahf/vczjk/f43;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    check-cast p2, Llyiahf/vczjk/zk1;

    iget p0, p2, Llyiahf/vczjk/zk1;->OooO00o:I

    new-instance p1, Ljava/lang/Integer;

    invoke-direct {p1, p0}, Ljava/lang/Integer;-><init>(I)V

    return-object p1
.end method
