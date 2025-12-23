.class public final Llyiahf/vczjk/wk2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $failedCommand:Llyiahf/vczjk/vk2;

.field final synthetic this$0:Llyiahf/vczjk/xk2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vk2;Llyiahf/vczjk/xk2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wk2;->$failedCommand:Llyiahf/vczjk/vk2;

    iput-object p2, p0, Llyiahf/vczjk/wk2;->this$0:Llyiahf/vczjk/xk2;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/vk2;

    iget-object v0, p0, Llyiahf/vczjk/wk2;->$failedCommand:Llyiahf/vczjk/vk2;

    if-ne v0, p1, :cond_0

    const-string v0, " > "

    goto :goto_0

    :cond_0
    const-string v0, "   "

    :goto_0
    invoke-static {v0}, Llyiahf/vczjk/ii5;->OooOOOO(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/wk2;->this$0:Llyiahf/vczjk/xk2;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v1, p1, Llyiahf/vczjk/n41;

    const/16 v2, 0x29

    const-string v3, ", newCursorPosition="

    if-eqz v1, :cond_1

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v4, "CommitTextCommand(text.length="

    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/n41;

    iget-object v4, p1, Llyiahf/vczjk/n41;->OooO00o:Llyiahf/vczjk/an;

    iget-object v4, v4, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v4}, Ljava/lang/String;->length()I

    move-result v4

    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget p1, p1, Llyiahf/vczjk/n41;->OooO0O0:I

    invoke-static {v1, p1, v2}, Llyiahf/vczjk/ix8;->OooO(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    move-result-object p1

    goto/16 :goto_1

    :cond_1
    instance-of v1, p1, Llyiahf/vczjk/ih8;

    if-eqz v1, :cond_2

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v4, "SetComposingTextCommand(text.length="

    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/ih8;

    iget-object v4, p1, Llyiahf/vczjk/ih8;->OooO00o:Llyiahf/vczjk/an;

    iget-object v4, v4, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v4}, Ljava/lang/String;->length()I

    move-result v4

    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget p1, p1, Llyiahf/vczjk/ih8;->OooO0O0:I

    invoke-static {v1, p1, v2}, Llyiahf/vczjk/ix8;->OooO(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    move-result-object p1

    goto :goto_1

    :cond_2
    instance-of v1, p1, Llyiahf/vczjk/hh8;

    if-eqz v1, :cond_3

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    goto :goto_1

    :cond_3
    instance-of v1, p1, Llyiahf/vczjk/y52;

    if-eqz v1, :cond_4

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    goto :goto_1

    :cond_4
    instance-of v1, p1, Llyiahf/vczjk/z52;

    if-eqz v1, :cond_5

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    goto :goto_1

    :cond_5
    instance-of v1, p1, Llyiahf/vczjk/jh8;

    if-eqz v1, :cond_6

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    goto :goto_1

    :cond_6
    instance-of v1, p1, Llyiahf/vczjk/o13;

    if-eqz v1, :cond_7

    check-cast p1, Llyiahf/vczjk/o13;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string p1, "FinishComposingTextCommand()"

    goto :goto_1

    :cond_7
    instance-of v1, p1, Llyiahf/vczjk/x52;

    if-eqz v1, :cond_8

    check-cast p1, Llyiahf/vczjk/x52;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string p1, "DeleteAllCommand()"

    goto :goto_1

    :cond_8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/gf4;->OooO0O0()Ljava/lang/String;

    move-result-object p1

    if-nez p1, :cond_9

    const-string p1, "{anonymous EditCommand}"

    :cond_9
    const-string v1, "Unknown EditCommand: "

    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    :goto_1
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method
