.class public final synthetic Llyiahf/vczjk/cu6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOOo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOo:Llyiahf/vczjk/le3;

.field public final synthetic OooOOo0:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOoo:Llyiahf/vczjk/le3;

.field public final synthetic OooOo00:Llyiahf/vczjk/qs5;


# direct methods
.method public synthetic constructor <init>(ILlyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;I)V
    .locals 0

    iput p8, p0, Llyiahf/vczjk/cu6;->OooOOO0:I

    iput p1, p0, Llyiahf/vczjk/cu6;->OooOOO:I

    iput-object p2, p0, Llyiahf/vczjk/cu6;->OooOOOO:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/cu6;->OooOOOo:Llyiahf/vczjk/qs5;

    iput-object p4, p0, Llyiahf/vczjk/cu6;->OooOOo0:Llyiahf/vczjk/oe3;

    iput-object p5, p0, Llyiahf/vczjk/cu6;->OooOOo:Llyiahf/vczjk/le3;

    iput-object p6, p0, Llyiahf/vczjk/cu6;->OooOOoo:Llyiahf/vczjk/le3;

    iput-object p7, p0, Llyiahf/vczjk/cu6;->OooOo00:Llyiahf/vczjk/qs5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 9

    iget v0, p0, Llyiahf/vczjk/cu6;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/cu6;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    const/4 v2, 0x6

    if-ge v1, v2, :cond_0

    iget-object v7, p0, Llyiahf/vczjk/cu6;->OooOOOo:Llyiahf/vczjk/qs5;

    const/4 v1, 0x0

    invoke-static {v7, v1}, Llyiahf/vczjk/fu6;->OooO0OO(Llyiahf/vczjk/qs5;Z)V

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    iget v3, p0, Llyiahf/vczjk/cu6;->OooOOO:I

    add-int/lit8 v3, v3, 0x7

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-interface {v0, v1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    if-ne v1, v2, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v8, v0

    check-cast v8, Ljava/lang/String;

    iget-object v6, p0, Llyiahf/vczjk/cu6;->OooOo00:Llyiahf/vczjk/qs5;

    iget-object v3, p0, Llyiahf/vczjk/cu6;->OooOOo0:Llyiahf/vczjk/oe3;

    iget-object v4, p0, Llyiahf/vczjk/cu6;->OooOOo:Llyiahf/vczjk/le3;

    iget-object v5, p0, Llyiahf/vczjk/cu6;->OooOOoo:Llyiahf/vczjk/le3;

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/fu6;->OooO0oO(Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Ljava/lang/String;)V

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/cu6;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    const/4 v2, 0x6

    if-ge v1, v2, :cond_1

    iget-object v7, p0, Llyiahf/vczjk/cu6;->OooOOOo:Llyiahf/vczjk/qs5;

    const/4 v1, 0x0

    invoke-static {v7, v1}, Llyiahf/vczjk/fu6;->OooO0OO(Llyiahf/vczjk/qs5;Z)V

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    iget v3, p0, Llyiahf/vczjk/cu6;->OooOOO:I

    add-int/lit8 v3, v3, 0x4

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-interface {v0, v1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    if-ne v1, v2, :cond_1

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v8, v0

    check-cast v8, Ljava/lang/String;

    iget-object v6, p0, Llyiahf/vczjk/cu6;->OooOo00:Llyiahf/vczjk/qs5;

    iget-object v3, p0, Llyiahf/vczjk/cu6;->OooOOo0:Llyiahf/vczjk/oe3;

    iget-object v4, p0, Llyiahf/vczjk/cu6;->OooOOo:Llyiahf/vczjk/le3;

    iget-object v5, p0, Llyiahf/vczjk/cu6;->OooOOoo:Llyiahf/vczjk/le3;

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/fu6;->OooO0oO(Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Ljava/lang/String;)V

    :cond_1
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/cu6;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    const/4 v2, 0x6

    if-ge v1, v2, :cond_2

    iget-object v7, p0, Llyiahf/vczjk/cu6;->OooOOOo:Llyiahf/vczjk/qs5;

    const/4 v1, 0x0

    invoke-static {v7, v1}, Llyiahf/vczjk/fu6;->OooO0OO(Llyiahf/vczjk/qs5;Z)V

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    iget v3, p0, Llyiahf/vczjk/cu6;->OooOOO:I

    add-int/lit8 v3, v3, 0x1

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-interface {v0, v1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    if-ne v1, v2, :cond_2

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v8, v0

    check-cast v8, Ljava/lang/String;

    iget-object v6, p0, Llyiahf/vczjk/cu6;->OooOo00:Llyiahf/vczjk/qs5;

    iget-object v3, p0, Llyiahf/vczjk/cu6;->OooOOo0:Llyiahf/vczjk/oe3;

    iget-object v4, p0, Llyiahf/vczjk/cu6;->OooOOo:Llyiahf/vczjk/le3;

    iget-object v5, p0, Llyiahf/vczjk/cu6;->OooOOoo:Llyiahf/vczjk/le3;

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/fu6;->OooO0oO(Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Ljava/lang/String;)V

    :cond_2
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
