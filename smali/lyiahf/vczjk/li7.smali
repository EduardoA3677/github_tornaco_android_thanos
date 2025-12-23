.class public final Llyiahf/vczjk/li7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/t24;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/kv3;

.field public final OooO0O0:Ljava/util/ArrayList;

.field public final OooO0OO:I

.field public final OooO0Oo:Llyiahf/vczjk/kv3;

.field public final OooO0o:Llyiahf/vczjk/jr2;

.field public final OooO0o0:Llyiahf/vczjk/sq8;

.field public final OooO0oO:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kv3;Ljava/util/ArrayList;ILlyiahf/vczjk/kv3;Llyiahf/vczjk/sq8;Llyiahf/vczjk/jr2;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/li7;->OooO00o:Llyiahf/vczjk/kv3;

    iput-object p2, p0, Llyiahf/vczjk/li7;->OooO0O0:Ljava/util/ArrayList;

    iput p3, p0, Llyiahf/vczjk/li7;->OooO0OO:I

    iput-object p4, p0, Llyiahf/vczjk/li7;->OooO0Oo:Llyiahf/vczjk/kv3;

    iput-object p5, p0, Llyiahf/vczjk/li7;->OooO0o0:Llyiahf/vczjk/sq8;

    iput-object p6, p0, Llyiahf/vczjk/li7;->OooO0o:Llyiahf/vczjk/jr2;

    iput-boolean p7, p0, Llyiahf/vczjk/li7;->OooO0oO:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/kv3;Llyiahf/vczjk/wn2;)V
    .locals 4

    iget-object v0, p1, Llyiahf/vczjk/kv3;->OooO00o:Landroid/content/Context;

    iget-object v1, p0, Llyiahf/vczjk/li7;->OooO00o:Llyiahf/vczjk/kv3;

    iget-object v2, v1, Llyiahf/vczjk/kv3;->OooO00o:Landroid/content/Context;

    const-string v3, "Interceptor \'"

    if-ne v0, v2, :cond_4

    sget-object v0, Llyiahf/vczjk/op3;->Oooo000:Llyiahf/vczjk/op3;

    iget-object v2, p1, Llyiahf/vczjk/kv3;->OooO0O0:Ljava/lang/Object;

    if-eq v2, v0, :cond_3

    iget-object v0, v1, Llyiahf/vczjk/kv3;->OooO0OO:Llyiahf/vczjk/eg9;

    iget-object v2, p1, Llyiahf/vczjk/kv3;->OooO0OO:Llyiahf/vczjk/eg9;

    if-ne v2, v0, :cond_2

    iget-object v0, v1, Llyiahf/vczjk/kv3;->OooOo0:Llyiahf/vczjk/ky4;

    iget-object v2, p1, Llyiahf/vczjk/kv3;->OooOo0:Llyiahf/vczjk/ky4;

    if-ne v2, v0, :cond_1

    iget-object v0, v1, Llyiahf/vczjk/kv3;->OooOo0O:Llyiahf/vczjk/ar8;

    iget-object p1, p1, Llyiahf/vczjk/kv3;->OooOo0O:Llyiahf/vczjk/ar8;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, "\' cannot modify the request\'s size resolver. Use `Interceptor.Chain.withSize` instead."

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_1
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, "\' cannot modify the request\'s lifecycle."

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_2
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, "\' cannot modify the request\'s target."

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_3
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, "\' cannot set the request\'s data to null."

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_4
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, "\' cannot modify the request\'s context."

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p2
.end method

.method public final OooO0O0(Llyiahf/vczjk/kv3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 12

    instance-of v0, p2, Llyiahf/vczjk/ji7;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/ji7;

    iget v1, v0, Llyiahf/vczjk/ji7;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/ji7;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ji7;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/ji7;-><init>(Llyiahf/vczjk/li7;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/ji7;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/ji7;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/ji7;->L$1:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/wn2;

    iget-object v0, v0, Llyiahf/vczjk/ji7;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/li7;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v6, p0, Llyiahf/vczjk/li7;->OooO0O0:Ljava/util/ArrayList;

    iget p2, p0, Llyiahf/vczjk/li7;->OooO0OO:I

    if-lez p2, :cond_3

    add-int/lit8 v2, p2, -0x1

    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/wn2;

    invoke-virtual {p0, p1, v2}, Llyiahf/vczjk/li7;->OooO00o(Llyiahf/vczjk/kv3;Llyiahf/vczjk/wn2;)V

    :cond_3
    invoke-virtual {v6, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/wn2;

    add-int/lit8 v7, p2, 0x1

    new-instance v4, Llyiahf/vczjk/li7;

    iget-object v9, p0, Llyiahf/vczjk/li7;->OooO0o0:Llyiahf/vczjk/sq8;

    iget-object v10, p0, Llyiahf/vczjk/li7;->OooO0o:Llyiahf/vczjk/jr2;

    iget-object v5, p0, Llyiahf/vczjk/li7;->OooO00o:Llyiahf/vczjk/kv3;

    iget-boolean v11, p0, Llyiahf/vczjk/li7;->OooO0oO:Z

    move-object v8, p1

    invoke-direct/range {v4 .. v11}, Llyiahf/vczjk/li7;-><init>(Llyiahf/vczjk/kv3;Ljava/util/ArrayList;ILlyiahf/vczjk/kv3;Llyiahf/vczjk/sq8;Llyiahf/vczjk/jr2;Z)V

    iput-object p0, v0, Llyiahf/vczjk/ji7;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ji7;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/ji7;->label:I

    invoke-virtual {v2, v4, v0}, Llyiahf/vczjk/wn2;->OooO0Oo(Llyiahf/vczjk/li7;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_4

    return-object v1

    :cond_4
    move-object v0, p0

    move-object p1, v2

    :goto_1
    check-cast p2, Llyiahf/vczjk/lv3;

    invoke-virtual {p2}, Llyiahf/vczjk/lv3;->OooO00o()Llyiahf/vczjk/kv3;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/li7;->OooO00o(Llyiahf/vczjk/kv3;Llyiahf/vczjk/wn2;)V

    return-object p2
.end method
