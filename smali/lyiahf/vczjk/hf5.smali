.class public final Llyiahf/vczjk/hf5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/kf5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kf5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hf5;->this$0:Llyiahf/vczjk/kf5;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/hf5;->this$0:Llyiahf/vczjk/kf5;

    iget-object v0, v0, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

    const/4 v1, 0x0

    iput v1, v0, Llyiahf/vczjk/vo4;->OooO:I

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

    iget-object v5, v5, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget v6, v5, Llyiahf/vczjk/kf5;->OooOo0:I

    iput v6, v5, Llyiahf/vczjk/kf5;->OooOo00:I

    iput v4, v5, Llyiahf/vczjk/kf5;->OooOo0:I

    iput-boolean v1, v5, Llyiahf/vczjk/kf5;->Oooo00O:Z

    iget-object v4, v5, Llyiahf/vczjk/kf5;->OooOo:Llyiahf/vczjk/no4;

    sget-object v6, Llyiahf/vczjk/no4;->OooOOO:Llyiahf/vczjk/no4;

    if-ne v4, v6, :cond_0

    sget-object v4, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    iput-object v4, v5, Llyiahf/vczjk/kf5;->OooOo:Llyiahf/vczjk/no4;

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/hf5;->this$0:Llyiahf/vczjk/kf5;

    iget-object v0, v0, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

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

    iget-object v5, v5, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-object v5, v5, Llyiahf/vczjk/kf5;->Oooo0OO:Llyiahf/vczjk/so4;

    iput-boolean v1, v5, Llyiahf/vczjk/v4;->OooO0Oo:Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/hf5;->this$0:Llyiahf/vczjk/kf5;

    invoke-virtual {v0}, Llyiahf/vczjk/kf5;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o000000()Llyiahf/vczjk/mf5;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/mf5;->OooO0O0()V

    iget-object v0, p0, Llyiahf/vczjk/hf5;->this$0:Llyiahf/vczjk/kf5;

    iget-object v0, v0, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v2

    iget-object v3, v2, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v2, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    move v5, v1

    :goto_2
    if-ge v5, v2, :cond_5

    aget-object v6, v3, v5

    check-cast v6, Llyiahf/vczjk/ro4;

    iget-object v7, v6, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v7, v7, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget v7, v7, Llyiahf/vczjk/kf5;->OooOo00:I

    invoke-virtual {v6}, Llyiahf/vczjk/ro4;->OooOo0o()I

    move-result v8

    if-eq v7, v8, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->Oooo0oO()V

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOoo()V

    invoke-virtual {v6}, Llyiahf/vczjk/ro4;->OooOo0o()I

    move-result v7

    if-ne v7, v4, :cond_4

    iget-object v6, v6, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-boolean v7, v6, Llyiahf/vczjk/vo4;->OooO0OO:Z

    if-eqz v7, :cond_3

    iget-object v7, v6, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v7}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v7, v1}, Llyiahf/vczjk/w65;->o00oO0O(Z)V

    :cond_3
    iget-object v6, v6, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    invoke-virtual {v6}, Llyiahf/vczjk/kf5;->o0OOO0o()V

    :cond_4
    add-int/lit8 v5, v5, 0x1

    goto :goto_2

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/hf5;->this$0:Llyiahf/vczjk/kf5;

    iget-object v0, v0, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v0

    iget-object v2, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    :goto_3
    if-ge v1, v0, :cond_6

    aget-object v3, v2, v1

    check-cast v3, Llyiahf/vczjk/ro4;

    iget-object v3, v3, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v3, v3, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-object v3, v3, Llyiahf/vczjk/kf5;->Oooo0OO:Llyiahf/vczjk/so4;

    iget-boolean v4, v3, Llyiahf/vczjk/v4;->OooO0Oo:Z

    iput-boolean v4, v3, Llyiahf/vczjk/v4;->OooO0o0:Z

    add-int/lit8 v1, v1, 0x1

    goto :goto_3

    :cond_6
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
