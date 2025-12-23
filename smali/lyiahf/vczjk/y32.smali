.class public final Llyiahf/vczjk/y32;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/y32;

.field public static final OooOOOO:Llyiahf/vczjk/y32;

.field public static final OooOOOo:Llyiahf/vczjk/y32;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/y32;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/y32;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/y32;->OooOOO:Llyiahf/vczjk/y32;

    new-instance v0, Llyiahf/vczjk/y32;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/y32;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/y32;->OooOOOO:Llyiahf/vczjk/y32;

    new-instance v0, Llyiahf/vczjk/y32;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/y32;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/y32;->OooOOOo:Llyiahf/vczjk/y32;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/y32;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Llyiahf/vczjk/oy6;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 0

    iget p1, p0, Llyiahf/vczjk/y32;->OooOOO0:I

    packed-switch p1, :pswitch_data_0

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
