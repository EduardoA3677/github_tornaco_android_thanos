.class public final enum Llyiahf/vczjk/pb4;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final synthetic OooOOO:[Llyiahf/vczjk/pb4;

.field public static final enum OooOOO0:Llyiahf/vczjk/pb4;


# instance fields
.field private final _defaultState:Z

.field private final _mappedFeature:Llyiahf/vczjk/cb4;

.field private final _mask:I


# direct methods
.method static constructor <clinit>()V
    .locals 14

    new-instance v0, Llyiahf/vczjk/pb4;

    sget-object v1, Llyiahf/vczjk/cb4;->OooOOO:Llyiahf/vczjk/cb4;

    const-string v2, "ALLOW_JAVA_COMMENTS"

    const/4 v3, 0x0

    invoke-direct {v0, v2, v3, v1}, Llyiahf/vczjk/pb4;-><init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V

    new-instance v1, Llyiahf/vczjk/pb4;

    sget-object v2, Llyiahf/vczjk/cb4;->OooOOOO:Llyiahf/vczjk/cb4;

    const-string v3, "ALLOW_YAML_COMMENTS"

    const/4 v4, 0x1

    invoke-direct {v1, v3, v4, v2}, Llyiahf/vczjk/pb4;-><init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V

    new-instance v2, Llyiahf/vczjk/pb4;

    sget-object v3, Llyiahf/vczjk/cb4;->OooOOo0:Llyiahf/vczjk/cb4;

    const-string v4, "ALLOW_SINGLE_QUOTES"

    const/4 v5, 0x2

    invoke-direct {v2, v4, v5, v3}, Llyiahf/vczjk/pb4;-><init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V

    new-instance v3, Llyiahf/vczjk/pb4;

    sget-object v4, Llyiahf/vczjk/cb4;->OooOOOo:Llyiahf/vczjk/cb4;

    const-string v5, "ALLOW_UNQUOTED_FIELD_NAMES"

    const/4 v6, 0x3

    invoke-direct {v3, v5, v6, v4}, Llyiahf/vczjk/pb4;-><init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V

    new-instance v4, Llyiahf/vczjk/pb4;

    sget-object v5, Llyiahf/vczjk/cb4;->OooOOo:Llyiahf/vczjk/cb4;

    const-string v6, "ALLOW_UNESCAPED_CONTROL_CHARS"

    const/4 v7, 0x4

    invoke-direct {v4, v6, v7, v5}, Llyiahf/vczjk/pb4;-><init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V

    new-instance v5, Llyiahf/vczjk/pb4;

    sget-object v6, Llyiahf/vczjk/cb4;->OooOOoo:Llyiahf/vczjk/cb4;

    const-string v7, "ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER"

    const/4 v8, 0x5

    invoke-direct {v5, v7, v8, v6}, Llyiahf/vczjk/pb4;-><init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V

    new-instance v6, Llyiahf/vczjk/pb4;

    sget-object v7, Llyiahf/vczjk/cb4;->OooOo00:Llyiahf/vczjk/cb4;

    const-string v8, "ALLOW_LEADING_ZEROS_FOR_NUMBERS"

    const/4 v9, 0x6

    invoke-direct {v6, v8, v9, v7}, Llyiahf/vczjk/pb4;-><init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V

    new-instance v7, Llyiahf/vczjk/pb4;

    sget-object v8, Llyiahf/vczjk/cb4;->OooOo0:Llyiahf/vczjk/cb4;

    const-string v9, "ALLOW_LEADING_DECIMAL_POINT_FOR_NUMBERS"

    const/4 v10, 0x7

    invoke-direct {v7, v9, v10, v8}, Llyiahf/vczjk/pb4;-><init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V

    sput-object v7, Llyiahf/vczjk/pb4;->OooOOO0:Llyiahf/vczjk/pb4;

    new-instance v8, Llyiahf/vczjk/pb4;

    sget-object v9, Llyiahf/vczjk/cb4;->OooOo0O:Llyiahf/vczjk/cb4;

    const-string v10, "ALLOW_NON_NUMERIC_NUMBERS"

    const/16 v11, 0x8

    invoke-direct {v8, v10, v11, v9}, Llyiahf/vczjk/pb4;-><init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V

    new-instance v9, Llyiahf/vczjk/pb4;

    sget-object v10, Llyiahf/vczjk/cb4;->OooOo0o:Llyiahf/vczjk/cb4;

    const-string v11, "ALLOW_MISSING_VALUES"

    const/16 v12, 0x9

    invoke-direct {v9, v11, v12, v10}, Llyiahf/vczjk/pb4;-><init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V

    new-instance v10, Llyiahf/vczjk/pb4;

    sget-object v11, Llyiahf/vczjk/cb4;->OooOo:Llyiahf/vczjk/cb4;

    const-string v12, "ALLOW_TRAILING_COMMA"

    const/16 v13, 0xa

    invoke-direct {v10, v12, v13, v11}, Llyiahf/vczjk/pb4;-><init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V

    filled-new-array/range {v0 .. v10}, [Llyiahf/vczjk/pb4;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/pb4;->OooOOO:[Llyiahf/vczjk/pb4;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILlyiahf/vczjk/cb4;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/pb4;->_defaultState:Z

    const/4 p1, 0x1

    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    shl-int/2addr p1, p2

    iput p1, p0, Llyiahf/vczjk/pb4;->_mask:I

    iput-object p3, p0, Llyiahf/vczjk/pb4;->_mappedFeature:Llyiahf/vczjk/cb4;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/pb4;
    .locals 1

    const-class v0, Llyiahf/vczjk/pb4;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/pb4;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/pb4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/pb4;->OooOOO:[Llyiahf/vczjk/pb4;

    invoke-virtual {v0}, [Llyiahf/vczjk/pb4;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/pb4;

    return-object v0
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/cb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pb4;->_mappedFeature:Llyiahf/vczjk/cb4;

    return-object v0
.end method
