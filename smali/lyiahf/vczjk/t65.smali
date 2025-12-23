.class public final Llyiahf/vczjk/t65;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $lookaheadDelegate:Llyiahf/vczjk/q65;

.field final synthetic this$0:Llyiahf/vczjk/w65;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w65;Llyiahf/vczjk/a04;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/t65;->this$0:Llyiahf/vczjk/w65;

    iput-object p2, p0, Llyiahf/vczjk/t65;->$lookaheadDelegate:Llyiahf/vczjk/q65;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/t65;->this$0:Llyiahf/vczjk/w65;

    iget-object v0, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    const/4 v1, 0x0

    iput v1, v0, Llyiahf/vczjk/vo4;->OooO0oo:I

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v0

    iget-object v2, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    move v3, v1

    :goto_0
    const v4, 0x7fffffff

    if-ge v3, v0, :cond_1

    aget-object v5, v2, v3

    check-cast v5, Llyiahf/vczjk/ro4;

    iget-object v5, v5, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v5, v5, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget v6, v5, Llyiahf/vczjk/w65;->OooOo0:I

    iput v6, v5, Llyiahf/vczjk/w65;->OooOo00:I

    iput v4, v5, Llyiahf/vczjk/w65;->OooOo0:I

    iget-object v4, v5, Llyiahf/vczjk/w65;->OooOo0O:Llyiahf/vczjk/no4;

    sget-object v6, Llyiahf/vczjk/no4;->OooOOO:Llyiahf/vczjk/no4;

    if-ne v4, v6, :cond_0

    sget-object v4, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    iput-object v4, v5, Llyiahf/vczjk/w65;->OooOo0O:Llyiahf/vczjk/no4;

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/t65;->this$0:Llyiahf/vczjk/w65;

    iget-object v0, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v0

    iget-object v2, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    move v3, v1

    :goto_1
    if-ge v3, v0, :cond_2

    aget-object v5, v2, v3

    check-cast v5, Llyiahf/vczjk/ro4;

    iget-object v5, v5, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v5, v5, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v5, v5, Llyiahf/vczjk/w65;->OooOooo:Llyiahf/vczjk/so4;

    iput-boolean v1, v5, Llyiahf/vczjk/v4;->OooO0Oo:Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/t65;->this$0:Llyiahf/vczjk/w65;

    invoke-virtual {v0}, Llyiahf/vczjk/w65;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/b04;->OoooOoo:Llyiahf/vczjk/a04;

    if-eqz v0, :cond_4

    iget-boolean v0, v0, Llyiahf/vczjk/o65;->OooOo00:Z

    iget-object v2, p0, Llyiahf/vczjk/t65;->this$0:Llyiahf/vczjk/w65;

    iget-object v2, v2, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v2, v2, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v2}, Llyiahf/vczjk/ro4;->OooOOOO()Ljava/util/List;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ts5;

    iget-object v3, v2, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v3, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    move v5, v1

    :goto_2
    if-ge v5, v3, :cond_4

    invoke-virtual {v2, v5}, Llyiahf/vczjk/ts5;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/ro4;

    iget-object v6, v6, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v6, v6, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/v16;

    invoke-virtual {v6}, Llyiahf/vczjk/v16;->o0000O0()Llyiahf/vczjk/q65;

    move-result-object v6

    if-nez v6, :cond_3

    goto :goto_3

    :cond_3
    iput-boolean v0, v6, Llyiahf/vczjk/o65;->OooOo00:Z

    :goto_3
    add-int/lit8 v5, v5, 0x1

    goto :goto_2

    :cond_4
    iget-object v0, p0, Llyiahf/vczjk/t65;->$lookaheadDelegate:Llyiahf/vczjk/q65;

    invoke-virtual {v0}, Llyiahf/vczjk/q65;->o000000()Llyiahf/vczjk/mf5;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/mf5;->OooO0O0()V

    iget-object v0, p0, Llyiahf/vczjk/t65;->this$0:Llyiahf/vczjk/w65;

    invoke-virtual {v0}, Llyiahf/vczjk/w65;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/b04;->OoooOoo:Llyiahf/vczjk/a04;

    if-eqz v0, :cond_6

    iget-object v0, p0, Llyiahf/vczjk/t65;->this$0:Llyiahf/vczjk/w65;

    iget-object v0, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOOO()Ljava/util/List;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ts5;

    iget-object v2, v0, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v2, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    move v3, v1

    :goto_4
    if-ge v3, v2, :cond_6

    invoke-virtual {v0, v3}, Llyiahf/vczjk/ts5;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ro4;

    iget-object v5, v5, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v5, v5, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/v16;

    invoke-virtual {v5}, Llyiahf/vczjk/v16;->o0000O0()Llyiahf/vczjk/q65;

    move-result-object v5

    if-nez v5, :cond_5

    goto :goto_5

    :cond_5
    iput-boolean v1, v5, Llyiahf/vczjk/o65;->OooOo00:Z

    :goto_5
    add-int/lit8 v3, v3, 0x1

    goto :goto_4

    :cond_6
    iget-object v0, p0, Llyiahf/vczjk/t65;->this$0:Llyiahf/vczjk/w65;

    iget-object v0, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v0

    iget-object v2, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    move v3, v1

    :goto_6
    if-ge v3, v0, :cond_8

    aget-object v5, v2, v3

    check-cast v5, Llyiahf/vczjk/ro4;

    iget-object v5, v5, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v5, v5, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget v6, v5, Llyiahf/vczjk/w65;->OooOo00:I

    iget v7, v5, Llyiahf/vczjk/w65;->OooOo0:I

    if-eq v6, v7, :cond_7

    if-ne v7, v4, :cond_7

    const/4 v6, 0x1

    invoke-virtual {v5, v6}, Llyiahf/vczjk/w65;->o00oO0O(Z)V

    :cond_7
    add-int/lit8 v3, v3, 0x1

    goto :goto_6

    :cond_8
    iget-object v0, p0, Llyiahf/vczjk/t65;->this$0:Llyiahf/vczjk/w65;

    iget-object v0, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v0

    iget-object v2, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    :goto_7
    if-ge v1, v0, :cond_9

    aget-object v3, v2, v1

    check-cast v3, Llyiahf/vczjk/ro4;

    iget-object v3, v3, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v3, v3, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v3, v3, Llyiahf/vczjk/w65;->OooOooo:Llyiahf/vczjk/so4;

    iget-boolean v4, v3, Llyiahf/vczjk/v4;->OooO0Oo:Z

    iput-boolean v4, v3, Llyiahf/vczjk/v4;->OooO0o0:Z

    add-int/lit8 v1, v1, 0x1

    goto :goto_7

    :cond_9
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
