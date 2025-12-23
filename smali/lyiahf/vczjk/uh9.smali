.class public final enum Llyiahf/vczjk/uh9;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/uh9;

.field public static final enum OooOOO0:Llyiahf/vczjk/uh9;

.field public static final enum OooOOOO:Llyiahf/vczjk/uh9;

.field public static final enum OooOOOo:Llyiahf/vczjk/uh9;

.field public static final synthetic OooOOo:[Llyiahf/vczjk/uh9;

.field public static final enum OooOOo0:Llyiahf/vczjk/uh9;


# instance fields
.field private final stringId:I


# direct methods
.method static constructor <clinit>()V
    .locals 8

    new-instance v0, Llyiahf/vczjk/uh9;

    const v1, 0x1040003

    const-string v2, "Cut"

    const/4 v3, 0x0

    invoke-direct {v0, v2, v3, v1}, Llyiahf/vczjk/uh9;-><init>(Ljava/lang/String;II)V

    sput-object v0, Llyiahf/vczjk/uh9;->OooOOO0:Llyiahf/vczjk/uh9;

    new-instance v1, Llyiahf/vczjk/uh9;

    const v2, 0x1040001

    const-string v3, "Copy"

    const/4 v4, 0x1

    invoke-direct {v1, v3, v4, v2}, Llyiahf/vczjk/uh9;-><init>(Ljava/lang/String;II)V

    sput-object v1, Llyiahf/vczjk/uh9;->OooOOO:Llyiahf/vczjk/uh9;

    new-instance v2, Llyiahf/vczjk/uh9;

    const v3, 0x104000b

    const-string v4, "Paste"

    const/4 v5, 0x2

    invoke-direct {v2, v4, v5, v3}, Llyiahf/vczjk/uh9;-><init>(Ljava/lang/String;II)V

    sput-object v2, Llyiahf/vczjk/uh9;->OooOOOO:Llyiahf/vczjk/uh9;

    new-instance v3, Llyiahf/vczjk/uh9;

    const v4, 0x104000d

    const-string v5, "SelectAll"

    const/4 v6, 0x3

    invoke-direct {v3, v5, v6, v4}, Llyiahf/vczjk/uh9;-><init>(Ljava/lang/String;II)V

    sput-object v3, Llyiahf/vczjk/uh9;->OooOOOo:Llyiahf/vczjk/uh9;

    new-instance v4, Llyiahf/vczjk/uh9;

    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v6, 0x1a

    if-gt v5, v6, :cond_0

    sget v5, Landroidx/compose/foundation/R$string;->autofill:I

    goto :goto_0

    :cond_0
    const v5, 0x104001a

    :goto_0
    const-string v6, "Autofill"

    const/4 v7, 0x4

    invoke-direct {v4, v6, v7, v5}, Llyiahf/vczjk/uh9;-><init>(Ljava/lang/String;II)V

    sput-object v4, Llyiahf/vczjk/uh9;->OooOOo0:Llyiahf/vczjk/uh9;

    filled-new-array {v0, v1, v2, v3, v4}, [Llyiahf/vczjk/uh9;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/uh9;->OooOOo:[Llyiahf/vczjk/uh9;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput p3, p0, Llyiahf/vczjk/uh9;->stringId:I

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/uh9;
    .locals 1

    const-class v0, Llyiahf/vczjk/uh9;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/uh9;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/uh9;
    .locals 1

    sget-object v0, Llyiahf/vczjk/uh9;->OooOOo:[Llyiahf/vczjk/uh9;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/uh9;

    return-object v0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/zf1;)Ljava/lang/String;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/uh9;->stringId:I

    invoke-static {v0, p1}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method
