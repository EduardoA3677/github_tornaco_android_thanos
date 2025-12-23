.class public final Llyiahf/vczjk/q48;
.super Llyiahf/vczjk/o000;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/q48;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/el1;)V
    .locals 0

    const/4 p1, 0x1

    iput p1, p0, Llyiahf/vczjk/q48;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/i16;)Ljava/lang/Object;
    .locals 6

    iget v0, p0, Llyiahf/vczjk/q48;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/p78;

    iget-object p1, p1, Llyiahf/vczjk/p78;->OooO0oo:Ljava/lang/String;

    sget-object v0, Llyiahf/vczjk/el1;->OooOOo0:Ljava/util/HashMap;

    invoke-virtual {p1}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/jl1;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "could not determine a constructor for the tag "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v2, p1, Llyiahf/vczjk/i16;->OooO00o:Llyiahf/vczjk/ye9;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    iget-object v4, p1, Llyiahf/vczjk/i16;->OooO0O0:Llyiahf/vczjk/mc5;

    const/4 v5, 0x0

    const/4 v1, 0x0

    move-object v2, v1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/sc5;-><init>(Ljava/lang/String;Llyiahf/vczjk/mc5;Ljava/lang/String;Llyiahf/vczjk/mc5;Ljava/lang/Exception;)V

    throw v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
