.class public final Llyiahf/vczjk/e41;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/g41;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g41;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/e41;->this$0:Llyiahf/vczjk/g41;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/e41;

    iget-object v0, p0, Llyiahf/vczjk/e41;->this$0:Llyiahf/vczjk/g41;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/e41;-><init>(Llyiahf/vczjk/g41;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/e41;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/e41;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/e41;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/e41;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/e41;->this$0:Llyiahf/vczjk/g41;

    sget-object v1, Llyiahf/vczjk/ch1;->OooOOoo:Llyiahf/vczjk/l39;

    invoke-static {p1, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gga;

    invoke-interface {p1}, Llyiahf/vczjk/gga;->OooO0O0()J

    move-result-wide v3

    iput v2, p0, Llyiahf/vczjk/e41;->label:I

    invoke-static {v3, v4, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/e41;->this$0:Llyiahf/vczjk/g41;

    iget-object p1, p1, Llyiahf/vczjk/g41;->OoooOO0:Llyiahf/vczjk/le3;

    if-eqz p1, :cond_3

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
