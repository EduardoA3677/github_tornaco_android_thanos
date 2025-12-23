.class public final synthetic Llyiahf/vczjk/w7a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lorg/apache/commons/io/function/IORunnable;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/w7a;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/w7a;->OooO0O0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/w7a;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/w7a;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Lorg/apache/commons/io/function/IOIterator;

    invoke-interface {v0}, Lorg/apache/commons/io/function/IOIterator;->remove()V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/w7a;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Lorg/apache/commons/io/input/UncheckedBufferedReader;

    invoke-static {v0}, Lorg/apache/commons/io/input/UncheckedBufferedReader;->OooOoO(Lorg/apache/commons/io/input/UncheckedBufferedReader;)V

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/w7a;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Lorg/apache/commons/io/input/UncheckedBufferedReader;

    invoke-static {v0}, Lorg/apache/commons/io/input/UncheckedBufferedReader;->OooOoOO(Lorg/apache/commons/io/input/UncheckedBufferedReader;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
