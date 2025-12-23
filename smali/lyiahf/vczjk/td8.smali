.class public final Llyiahf/vczjk/td8;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $clicksCounter:Llyiahf/vczjk/zz0;

.field final synthetic $mouseSelectionObserver:Llyiahf/vczjk/dp5;

.field final synthetic $textDragObserver:Llyiahf/vczjk/bi9;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dp5;Llyiahf/vczjk/zz0;Llyiahf/vczjk/bi9;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/td8;->$mouseSelectionObserver:Llyiahf/vczjk/dp5;

    iput-object p2, p0, Llyiahf/vczjk/td8;->$clicksCounter:Llyiahf/vczjk/zz0;

    iput-object p3, p0, Llyiahf/vczjk/td8;->$textDragObserver:Llyiahf/vczjk/bi9;

    invoke-direct {p0, p4}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/td8;

    iget-object v1, p0, Llyiahf/vczjk/td8;->$mouseSelectionObserver:Llyiahf/vczjk/dp5;

    iget-object v2, p0, Llyiahf/vczjk/td8;->$clicksCounter:Llyiahf/vczjk/zz0;

    iget-object v3, p0, Llyiahf/vczjk/td8;->$textDragObserver:Llyiahf/vczjk/bi9;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/td8;-><init>(Llyiahf/vczjk/dp5;Llyiahf/vczjk/zz0;Llyiahf/vczjk/bi9;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/td8;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kb9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/td8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/td8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/td8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/td8;->label:I

    const/4 v2, 0x1

    const/4 v3, 0x3

    const/4 v4, 0x2

    if-eqz v1, :cond_3

    if-eq v1, v2, :cond_2

    if-eq v1, v4, :cond_1

    if-ne v1, v3, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_5

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/td8;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/kb9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/td8;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/kb9;

    iput-object v1, p0, Llyiahf/vczjk/td8;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/td8;->label:I

    invoke-static {v1, p0}, Llyiahf/vczjk/m6a;->OooOOO0(Llyiahf/vczjk/kb9;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    goto :goto_4

    :cond_4
    :goto_1
    check-cast p1, Llyiahf/vczjk/ey6;

    invoke-static {p1}, Llyiahf/vczjk/m6a;->oo000o(Llyiahf/vczjk/ey6;)Z

    move-result v2

    const/4 v5, 0x0

    if-eqz v2, :cond_7

    iget v2, p1, Llyiahf/vczjk/ey6;->OooO0OO:I

    and-int/lit8 v2, v2, 0x21

    if-eqz v2, :cond_7

    iget-object v2, p1, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v6

    const/4 v7, 0x0

    :goto_2
    if-ge v7, v6, :cond_6

    invoke-interface {v2, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/ky6;

    invoke-virtual {v8}, Llyiahf/vczjk/ky6;->OooO0O0()Z

    move-result v8

    if-eqz v8, :cond_5

    goto :goto_3

    :cond_5
    add-int/lit8 v7, v7, 0x1

    goto :goto_2

    :cond_6
    iget-object v2, p0, Llyiahf/vczjk/td8;->$mouseSelectionObserver:Llyiahf/vczjk/dp5;

    iget-object v3, p0, Llyiahf/vczjk/td8;->$clicksCounter:Llyiahf/vczjk/zz0;

    iput-object v5, p0, Llyiahf/vczjk/td8;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/td8;->label:I

    invoke-static {v1, v2, v3, p1, p0}, Llyiahf/vczjk/m6a;->OooOOOO(Llyiahf/vczjk/kb9;Llyiahf/vczjk/dp5;Llyiahf/vczjk/zz0;Llyiahf/vczjk/ey6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_8

    goto :goto_4

    :cond_7
    :goto_3
    invoke-static {p1}, Llyiahf/vczjk/m6a;->oo000o(Llyiahf/vczjk/ey6;)Z

    move-result v2

    if-nez v2, :cond_8

    iget-object v2, p0, Llyiahf/vczjk/td8;->$textDragObserver:Llyiahf/vczjk/bi9;

    iput-object v5, p0, Llyiahf/vczjk/td8;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/td8;->label:I

    invoke-static {v1, v2, p1, p0}, Llyiahf/vczjk/m6a;->OooOOOo(Llyiahf/vczjk/kb9;Llyiahf/vczjk/bi9;Llyiahf/vczjk/ey6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_8

    :goto_4
    return-object v0

    :cond_8
    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
