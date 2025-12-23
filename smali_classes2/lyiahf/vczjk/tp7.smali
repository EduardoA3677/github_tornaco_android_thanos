.class public final Llyiahf/vczjk/tp7;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $down:J

.field final synthetic $onDrag:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $onDragCancel:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $onDragEnd:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(JLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-wide p1, p0, Llyiahf/vczjk/tp7;->$down:J

    iput-object p3, p0, Llyiahf/vczjk/tp7;->$onDragEnd:Llyiahf/vczjk/le3;

    iput-object p4, p0, Llyiahf/vczjk/tp7;->$onDragCancel:Llyiahf/vczjk/le3;

    iput-object p5, p0, Llyiahf/vczjk/tp7;->$onDrag:Llyiahf/vczjk/ze3;

    invoke-direct {p0, p6}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/tp7;

    iget-wide v1, p0, Llyiahf/vczjk/tp7;->$down:J

    iget-object v3, p0, Llyiahf/vczjk/tp7;->$onDragEnd:Llyiahf/vczjk/le3;

    iget-object v4, p0, Llyiahf/vczjk/tp7;->$onDragCancel:Llyiahf/vczjk/le3;

    iget-object v5, p0, Llyiahf/vczjk/tp7;->$onDrag:Llyiahf/vczjk/ze3;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/tp7;-><init>(JLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/tp7;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kb9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/tp7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tp7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/tp7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/tp7;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tp7;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/kb9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/tp7;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/kb9;

    iget-wide v3, p0, Llyiahf/vczjk/tp7;->$down:J

    iget-object v1, p0, Llyiahf/vczjk/tp7;->$onDrag:Llyiahf/vczjk/ze3;

    new-instance v5, Llyiahf/vczjk/w45;

    const/16 v6, 0xe

    invoke-direct {v5, v1, v6}, Llyiahf/vczjk/w45;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Llyiahf/vczjk/tp7;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/tp7;->label:I

    invoke-static {p1, v3, v4, v5, p0}, Llyiahf/vczjk/ve2;->OooO0OO(Llyiahf/vczjk/kb9;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_2

    return-object v0

    :cond_2
    move-object v0, p1

    move-object p1, v1

    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_5

    iget-object p1, v0, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    iget-object p1, p1, Llyiahf/vczjk/nb9;->OooOooo:Llyiahf/vczjk/ey6;

    iget-object p1, p1, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_3
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ky6;

    invoke-static {v0}, Llyiahf/vczjk/vl6;->OooO(Llyiahf/vczjk/ky6;)Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-virtual {v0}, Llyiahf/vczjk/ky6;->OooO00o()V

    goto :goto_1

    :cond_4
    iget-object p1, p0, Llyiahf/vczjk/tp7;->$onDragEnd:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    goto :goto_2

    :cond_5
    iget-object p1, p0, Llyiahf/vczjk/tp7;->$onDragCancel:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
