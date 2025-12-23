.class public final Llyiahf/vczjk/b62;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wf8;


# instance fields
.field public final synthetic OooO00o:I

.field public final OooO0O0:Ljava/lang/Object;

.field public final OooO0OO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/b62;->OooO00o:I

    iput-object p2, p0, Llyiahf/vczjk/b62;->OooO0O0:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/b62;->OooO0OO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/CharSequence;Llyiahf/vczjk/ze3;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/b62;->OooO00o:I

    const-string v0, "input"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/b62;->OooO0O0:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/b62;->OooO0OO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Llyiahf/vczjk/b62;->OooO00o:I

    const-string v0, "sequence"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/b62;->OooO0O0:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/b62;->OooO0OO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/b62;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/d13;

    invoke-direct {v0, p0}, Llyiahf/vczjk/d13;-><init>(Llyiahf/vczjk/b62;)V

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/b62;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/e13;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v0}, Llyiahf/vczjk/e13;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/d13;

    invoke-virtual {v2}, Llyiahf/vczjk/d13;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-virtual {v2}, Llyiahf/vczjk/d13;->next()Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/b62;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ib;

    invoke-static {v1, v0}, Llyiahf/vczjk/i21;->OoooOOo(Ljava/util/List;Ljava/util/Comparator;)V

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    return-object v0

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/zg3;

    invoke-direct {v0, p0}, Llyiahf/vczjk/zg3;-><init>(Llyiahf/vczjk/b62;)V

    return-object v0

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/a62;

    invoke-direct {v0, p0}, Llyiahf/vczjk/a62;-><init>(Llyiahf/vczjk/b62;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
