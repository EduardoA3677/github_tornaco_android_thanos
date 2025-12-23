.class public final Llyiahf/vczjk/fk4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/hk4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/hk4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/fk4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/fk4;->OooOOO:Llyiahf/vczjk/hk4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 14

    const/4 v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/fk4;->OooOOO:Llyiahf/vczjk/hk4;

    const/4 v2, 0x0

    iget v3, p0, Llyiahf/vczjk/fk4;->OooOOO0:I

    packed-switch v3, :pswitch_data_0

    new-instance v3, Ljava/util/EnumMap;

    const-class v4, Llyiahf/vczjk/q47;

    invoke-direct {v3, v4}, Ljava/util/EnumMap;-><init>(Ljava/lang/Class;)V

    new-instance v4, Ljava/util/HashMap;

    invoke-direct {v4}, Ljava/util/HashMap;-><init>()V

    new-instance v5, Ljava/util/HashMap;

    invoke-direct {v5}, Ljava/util/HashMap;-><init>()V

    invoke-static {}, Llyiahf/vczjk/q47;->values()[Llyiahf/vczjk/q47;

    move-result-object v6

    array-length v7, v6

    :goto_0
    if-ge v2, v7, :cond_4

    aget-object v8, v6, v2

    invoke-virtual {v8}, Llyiahf/vczjk/q47;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v9

    invoke-virtual {v9}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v9

    const/16 v10, 0x2f

    const/4 v11, 0x0

    if-eqz v9, :cond_3

    invoke-virtual {v1, v9}, Llyiahf/vczjk/hk4;->OooOO0O(Ljava/lang/String;)Llyiahf/vczjk/by0;

    move-result-object v9

    invoke-interface {v9}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v9

    const/16 v12, 0x30

    if-eqz v9, :cond_2

    invoke-virtual {v8}, Llyiahf/vczjk/q47;->OooO0Oo()Llyiahf/vczjk/qt5;

    move-result-object v13

    invoke-virtual {v13}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v13

    if-eqz v13, :cond_1

    invoke-virtual {v1, v13}, Llyiahf/vczjk/hk4;->OooOO0O(Ljava/lang/String;)Llyiahf/vczjk/by0;

    move-result-object v10

    invoke-interface {v10}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v10

    if-eqz v10, :cond_0

    invoke-virtual {v3, v8, v10}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v4, v9, v10}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v5, v10, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/2addr v2, v0

    goto :goto_0

    :cond_0
    invoke-static {v12}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v11

    :cond_1
    invoke-static {v10}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v11

    :cond_2
    invoke-static {v12}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v11

    :cond_3
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v10}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v11

    :cond_4
    new-instance v0, Llyiahf/vczjk/gk4;

    invoke-direct {v0, v3, v4, v5}, Llyiahf/vczjk/gk4;-><init>(Ljava/util/EnumMap;Ljava/util/HashMap;Ljava/util/HashMap;)V

    return-object v0

    :pswitch_0
    invoke-virtual {v1}, Llyiahf/vczjk/hk4;->OooOO0o()Llyiahf/vczjk/dm5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/x09;->OooOO0o:Llyiahf/vczjk/hc3;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/dm5;->OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;

    move-result-object v3

    invoke-virtual {v1}, Llyiahf/vczjk/hk4;->OooOO0o()Llyiahf/vczjk/dm5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/x09;->OooOOO:Llyiahf/vczjk/hc3;

    invoke-virtual {v4, v5}, Llyiahf/vczjk/dm5;->OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;

    move-result-object v4

    invoke-virtual {v1}, Llyiahf/vczjk/hk4;->OooOO0o()Llyiahf/vczjk/dm5;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/x09;->OooOOOO:Llyiahf/vczjk/hc3;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/dm5;->OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;

    move-result-object v5

    invoke-virtual {v1}, Llyiahf/vczjk/hk4;->OooOO0o()Llyiahf/vczjk/dm5;

    move-result-object v1

    sget-object v6, Llyiahf/vczjk/x09;->OooOOO0:Llyiahf/vczjk/hc3;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/dm5;->OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;

    move-result-object v1

    const/4 v6, 0x4

    new-array v6, v6, [Llyiahf/vczjk/vh6;

    aput-object v3, v6, v2

    aput-object v4, v6, v0

    const/4 v0, 0x2

    aput-object v5, v6, v0

    const/4 v0, 0x3

    aput-object v1, v6, v0

    invoke-static {v6}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
