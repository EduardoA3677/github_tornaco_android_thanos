.class public final Llyiahf/vczjk/ar1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $this_applySemantics:Llyiahf/vczjk/af8;

.field final synthetic this$0:Llyiahf/vczjk/hr1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hr1;Llyiahf/vczjk/af8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ar1;->this$0:Llyiahf/vczjk/hr1;

    iput-object p2, p0, Llyiahf/vczjk/ar1;->$this_applySemantics:Llyiahf/vczjk/af8;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    const/4 v0, 0x0

    const/4 v1, 0x1

    check-cast p1, Llyiahf/vczjk/an;

    iget-object v2, p0, Llyiahf/vczjk/ar1;->this$0:Llyiahf/vczjk/hr1;

    iget-boolean v3, v2, Llyiahf/vczjk/hr1;->Oooo000:Z

    if-nez v3, :cond_4

    iget-boolean v3, v2, Llyiahf/vczjk/hr1;->Oooo00O:Z

    if-nez v3, :cond_0

    goto/16 :goto_1

    :cond_0
    iget-object v3, v2, Llyiahf/vczjk/hr1;->OooOooo:Llyiahf/vczjk/lx4;

    iget-object v3, v3, Llyiahf/vczjk/lx4;->OooO0o0:Llyiahf/vczjk/yl9;

    const/4 v4, 0x0

    if-eqz v3, :cond_1

    new-instance v5, Llyiahf/vczjk/o13;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    new-instance v6, Llyiahf/vczjk/n41;

    invoke-direct {v6, p1, v1}, Llyiahf/vczjk/n41;-><init>(Llyiahf/vczjk/an;I)V

    const/4 v7, 0x2

    new-array v7, v7, [Llyiahf/vczjk/vk2;

    aput-object v5, v7, v0

    aput-object v6, v7, v1

    invoke-static {v7}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    iget-object v2, v2, Llyiahf/vczjk/hr1;->OooOooo:Llyiahf/vczjk/lx4;

    iget-object v5, v2, Llyiahf/vczjk/lx4;->OooO0Oo:Llyiahf/vczjk/xk2;

    invoke-virtual {v5, v1}, Llyiahf/vczjk/xk2;->OooO00o(Ljava/util/List;)Llyiahf/vczjk/gl9;

    move-result-object v1

    invoke-virtual {v3, v4, v1}, Llyiahf/vczjk/yl9;->OooO00o(Llyiahf/vczjk/gl9;Llyiahf/vczjk/gl9;)V

    iget-object v2, v2, Llyiahf/vczjk/lx4;->OooOo0O:Llyiahf/vczjk/kx4;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/kx4;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v4, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :cond_1
    if-nez v4, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/ar1;->this$0:Llyiahf/vczjk/hr1;

    iget-object v2, v1, Llyiahf/vczjk/hr1;->OooOooO:Llyiahf/vczjk/gl9;

    iget-object v3, v2, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v3, v3, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    sget v4, Llyiahf/vczjk/gn9;->OooO0OO:I

    iget-wide v4, v2, Llyiahf/vczjk/gl9;->OooO0O0:J

    const/16 v2, 0x20

    shr-long v6, v4, v2

    long-to-int v6, v6

    const-wide v7, 0xffffffffL

    and-long/2addr v4, v7

    long-to-int v4, v4

    const-string v5, "<this>"

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "replacement"

    invoke-static {p1, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-lt v4, v6, :cond_2

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v5, v3, v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    invoke-virtual {v5, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v0

    invoke-virtual {v5, v3, v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    iget-object v3, v1, Llyiahf/vczjk/hr1;->OooOooO:Llyiahf/vczjk/gl9;

    iget-wide v3, v3, Llyiahf/vczjk/gl9;->OooO0O0:J

    shr-long v2, v3, v2

    long-to-int v2, v2

    iget-object p1, p1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p1

    add-int/2addr p1, v2

    invoke-static {p1, p1}, Llyiahf/vczjk/rd3;->OooO0O0(II)J

    move-result-wide v2

    iget-object p1, v1, Llyiahf/vczjk/hr1;->OooOooo:Llyiahf/vczjk/lx4;

    iget-object p1, p1, Llyiahf/vczjk/lx4;->OooOo0O:Llyiahf/vczjk/kx4;

    new-instance v1, Llyiahf/vczjk/gl9;

    const/4 v4, 0x4

    invoke-direct {v1, v0, v2, v3, v4}, Llyiahf/vczjk/gl9;-><init>(Ljava/lang/String;JI)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/kx4;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_2
    new-instance p1, Ljava/lang/IndexOutOfBoundsException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "End index ("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ") is less than start index ("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ")."

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    :goto_0
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :cond_4
    :goto_1
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1
.end method
