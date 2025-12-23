.class public final Llyiahf/vczjk/j75;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $composition:Llyiahf/vczjk/z75;

.field final synthetic $iteration:I

.field final synthetic $progress:F

.field final synthetic $resetLastFrameNanos:Z

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/k75;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k75;Llyiahf/vczjk/z75;FIZLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/j75;->this$0:Llyiahf/vczjk/k75;

    iput-object p2, p0, Llyiahf/vczjk/j75;->$composition:Llyiahf/vczjk/z75;

    iput p3, p0, Llyiahf/vczjk/j75;->$progress:F

    iput p4, p0, Llyiahf/vczjk/j75;->$iteration:I

    iput-boolean p5, p0, Llyiahf/vczjk/j75;->$resetLastFrameNanos:Z

    const/4 p1, 0x1

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/j75;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/j75;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/j75;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v0
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/j75;

    iget-object v1, p0, Llyiahf/vczjk/j75;->this$0:Llyiahf/vczjk/k75;

    iget-object v2, p0, Llyiahf/vczjk/j75;->$composition:Llyiahf/vczjk/z75;

    iget v3, p0, Llyiahf/vczjk/j75;->$progress:F

    iget v4, p0, Llyiahf/vczjk/j75;->$iteration:I

    iget-boolean v5, p0, Llyiahf/vczjk/j75;->$resetLastFrameNanos:Z

    move-object v6, p1

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/j75;-><init>(Llyiahf/vczjk/k75;Llyiahf/vczjk/z75;FIZLlyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/j75;->label:I

    if-nez v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/j75;->this$0:Llyiahf/vczjk/k75;

    iget-object v0, p0, Llyiahf/vczjk/j75;->$composition:Llyiahf/vczjk/z75;

    iget-object p1, p1, Llyiahf/vczjk/k75;->OooOo0:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/j75;->this$0:Llyiahf/vczjk/k75;

    iget v0, p0, Llyiahf/vczjk/j75;->$progress:F

    invoke-virtual {p1, v0}, Llyiahf/vczjk/k75;->OooO0oo(F)V

    iget-object p1, p0, Llyiahf/vczjk/j75;->this$0:Llyiahf/vczjk/k75;

    iget v0, p0, Llyiahf/vczjk/j75;->$iteration:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/k75;->OooO0oO(I)V

    iget-object p1, p0, Llyiahf/vczjk/j75;->this$0:Llyiahf/vczjk/k75;

    const/4 v0, 0x0

    invoke-static {p1, v0}, Llyiahf/vczjk/k75;->OooO0O0(Llyiahf/vczjk/k75;Z)V

    iget-boolean p1, p0, Llyiahf/vczjk/j75;->$resetLastFrameNanos:Z

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/j75;->this$0:Llyiahf/vczjk/k75;

    iget-object p1, p1, Llyiahf/vczjk/k75;->OooOo:Llyiahf/vczjk/qs5;

    const-wide/high16 v0, -0x8000000000000000L

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v0

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
