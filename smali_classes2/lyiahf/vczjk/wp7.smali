.class public final Llyiahf/vczjk/wp7;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $dragStart:Llyiahf/vczjk/r19;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/r19;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wp7;->$dragStart:Llyiahf/vczjk/r19;

    invoke-direct {p0, p2}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/wp7;

    iget-object v1, p0, Llyiahf/vczjk/wp7;->$dragStart:Llyiahf/vczjk/r19;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/wp7;-><init>(Llyiahf/vczjk/r19;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/wp7;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kb9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/wp7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wp7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/wp7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/wp7;->label:I

    if-nez v0, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/wp7;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/kb9;

    iget-object p1, p1, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    iget-object p1, p1, Llyiahf/vczjk/nb9;->OooOooo:Llyiahf/vczjk/ey6;

    iget-object p1, p1, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/wp7;->$dragStart:Llyiahf/vczjk/r19;

    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v1

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_1

    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/ky6;

    iget-wide v4, v4, Llyiahf/vczjk/ky6;->OooO00o:J

    iget-wide v6, v0, Llyiahf/vczjk/r19;->OooO00o:J

    invoke-static {v4, v5, v6, v7}, Llyiahf/vczjk/tn6;->OooO0oo(JJ)Z

    move-result v4

    if-eqz v4, :cond_0

    return-object v3

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    return-object p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
