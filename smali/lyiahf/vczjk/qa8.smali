.class public final Llyiahf/vczjk/qa8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field synthetic J$0:J

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ra8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ra8;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qa8;->this$0:Llyiahf/vczjk/ra8;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/qa8;

    iget-object v1, p0, Llyiahf/vczjk/qa8;->this$0:Llyiahf/vczjk/ra8;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/qa8;-><init>(Llyiahf/vczjk/ra8;Llyiahf/vczjk/yo1;)V

    check-cast p1, Llyiahf/vczjk/p86;

    iget-wide p1, p1, Llyiahf/vczjk/p86;->OooO00o:J

    iput-wide p1, v0, Llyiahf/vczjk/qa8;->J$0:J

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/p86;

    iget-wide v0, p1, Llyiahf/vczjk/p86;->OooO00o:J

    check-cast p2, Llyiahf/vczjk/yo1;

    new-instance p1, Llyiahf/vczjk/qa8;

    iget-object v2, p0, Llyiahf/vczjk/qa8;->this$0:Llyiahf/vczjk/ra8;

    invoke-direct {p1, v2, p2}, Llyiahf/vczjk/qa8;-><init>(Llyiahf/vczjk/ra8;Llyiahf/vczjk/yo1;)V

    iput-wide v0, p1, Llyiahf/vczjk/qa8;->J$0:J

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/qa8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/qa8;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-wide v3, p0, Llyiahf/vczjk/qa8;->J$0:J

    iget-object p1, p0, Llyiahf/vczjk/qa8;->this$0:Llyiahf/vczjk/ra8;

    iget-object p1, p1, Llyiahf/vczjk/ra8;->Oooo:Llyiahf/vczjk/db8;

    iput v2, p0, Llyiahf/vczjk/qa8;->label:I

    invoke-static {p1, v3, v4, p0}, Landroidx/compose/foundation/gestures/OooO0O0;->OooO00o(Llyiahf/vczjk/db8;JLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    return-object p1
.end method
