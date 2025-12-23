.class public final Llyiahf/vczjk/t42;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/hha;


# static fields
.field public static final OooO0O0:Llyiahf/vczjk/t42;


# instance fields
.field public final synthetic OooO00o:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/t42;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/t42;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/t42;->OooO0O0:Llyiahf/vczjk/t42;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/t42;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/gf4;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;
    .locals 0

    iget p2, p0, Llyiahf/vczjk/t42;->OooO00o:I

    packed-switch p2, :pswitch_data_0

    const-string p2, "modelClass"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/b68;

    invoke-direct {p1}, Llyiahf/vczjk/b68;-><init>()V

    return-object p1

    :pswitch_0
    const-string p2, "modelClass"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooOOOo(Ljava/lang/Class;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
