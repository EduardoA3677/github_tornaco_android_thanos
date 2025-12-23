.class public final Llyiahf/vczjk/f46;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/g46;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g46;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/f46;->this$0:Llyiahf/vczjk/g46;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/y36;

    check-cast p2, Llyiahf/vczjk/y36;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/f46;

    iget-object v1, p0, Llyiahf/vczjk/f46;->this$0:Llyiahf/vczjk/g46;

    invoke-direct {v0, v1, p3}, Llyiahf/vczjk/f46;-><init>(Llyiahf/vczjk/g46;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/f46;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/f46;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/f46;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/f46;->label:I

    if-nez v0, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/f46;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/y36;

    iget-object v0, p0, Llyiahf/vczjk/f46;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/y36;

    const/4 v1, 0x0

    if-nez p1, :cond_0

    if-nez v0, :cond_0

    return-object v1

    :cond_0
    if-nez v0, :cond_1

    return-object v1

    :cond_1
    if-nez p1, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/f46;->this$0:Llyiahf/vczjk/g46;

    invoke-static {p1, v0}, Llyiahf/vczjk/g46;->OooO00o(Llyiahf/vczjk/g46;Llyiahf/vczjk/y36;)Llyiahf/vczjk/x36;

    move-result-object p1

    return-object p1

    :cond_2
    iget-object p1, p1, Llyiahf/vczjk/y36;->OooO00o:Ljava/util/Date;

    iget-object v2, v0, Llyiahf/vczjk/y36;->OooO00o:Ljava/util/Date;

    invoke-static {p1, v2}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->isSameDay(Ljava/util/Date;Ljava/util/Date;)Z

    move-result p1

    if-nez p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/f46;->this$0:Llyiahf/vczjk/g46;

    invoke-static {p1, v0}, Llyiahf/vczjk/g46;->OooO00o(Llyiahf/vczjk/g46;Llyiahf/vczjk/y36;)Llyiahf/vczjk/x36;

    move-result-object p1

    return-object p1

    :cond_3
    return-object v1

    :cond_4
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
