.class public final Llyiahf/vczjk/yj9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/mk9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mk9;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/yj9;

    iget-object v0, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/yj9;-><init>(Llyiahf/vczjk/mk9;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/yj9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/yj9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/yj9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/yj9;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {p1}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object p1

    iget-wide v4, p1, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v4, v5}, Llyiahf/vczjk/gn9;->OooO0O0(J)Z

    move-result p1

    if-eqz p1, :cond_2

    return-object v2

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    iget-object v1, p1, Llyiahf/vczjk/mk9;->OooO0oo:Llyiahf/vczjk/c01;

    if-eqz v1, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/cl6;->OooO(Llyiahf/vczjk/gl9;)Llyiahf/vczjk/an;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/bua;->OoooO0O(Llyiahf/vczjk/an;)Llyiahf/vczjk/a01;

    move-result-object p1

    iput v3, p0, Llyiahf/vczjk/yj9;->label:I

    check-cast v1, Llyiahf/vczjk/v9;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/v9;->OooO00o(Llyiahf/vczjk/a01;)V

    if-ne v2, v0, :cond_3

    return-object v0

    :cond_3
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {p1}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v0, v0, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    invoke-static {p1, v0}, Llyiahf/vczjk/cl6;->OooOO0O(Llyiahf/vczjk/gl9;I)Llyiahf/vczjk/an;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {v1}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v1, v1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    invoke-static {v0, v1}, Llyiahf/vczjk/cl6;->OooOO0(Llyiahf/vczjk/gl9;I)Llyiahf/vczjk/an;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/ym;

    invoke-direct {v1, p1}, Llyiahf/vczjk/ym;-><init>(Llyiahf/vczjk/an;)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ym;->OooO0O0(Llyiahf/vczjk/an;)V

    invoke-virtual {v1}, Llyiahf/vczjk/ym;->OooO0OO()Llyiahf/vczjk/an;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v0

    iget-wide v0, v0, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v0, v1}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    invoke-static {v0, v0}, Llyiahf/vczjk/rd3;->OooO0O0(II)J

    move-result-wide v4

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, v4, v5}, Llyiahf/vczjk/mk9;->OooO0o0(Llyiahf/vczjk/an;J)Llyiahf/vczjk/gl9;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    iget-object v0, v0, Llyiahf/vczjk/mk9;->OooO0OO:Llyiahf/vczjk/rm4;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    sget-object v0, Llyiahf/vczjk/vl3;->OooOOO0:Llyiahf/vczjk/vl3;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mk9;->OooOOo0(Llyiahf/vczjk/vl3;)V

    iget-object p1, p0, Llyiahf/vczjk/yj9;->this$0:Llyiahf/vczjk/mk9;

    iget-object p1, p1, Llyiahf/vczjk/mk9;->OooO00o:Llyiahf/vczjk/l8a;

    iput-boolean v3, p1, Llyiahf/vczjk/l8a;->OooO0o0:Z

    return-object v2
.end method
